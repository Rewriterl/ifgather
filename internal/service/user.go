package service

import (
	"context"
	"database/sql"
	"errors"
	"github.com/Rewriterl/ifgather/internal/dao"
	"github.com/Rewriterl/ifgather/internal/model"
	"github.com/Rewriterl/ifgather/utility/logger"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
	"golang.org/x/crypto/bcrypt"
)

type serviceUser struct{}

var User = new(serviceUser)

func (s *serviceUser) Login(ctx context.Context, r *model.UsersApiLoginReq, ip, userAgent string) error {
	one, err := dao.Users.Ctx(ctx).One("username", r.Username)
	returnErr := errors.New("用户登录失败")
	if err != nil || one == nil {
		logger.WebLog.Warningf(ctx, "[%s] 用户 [%s] 登录失败", ip, r.Username)
		return returnErr
	}
	user, err := TransToUser(one)
	if !s.checkPassword(user.Password, r.Password) {
		logger.WebLog.Debugf(ctx, "[%s] 用户 [%s] 登录失败", ip, r.Username)
		return returnErr
	}
	if err := Session.SetUser(ctx, user); err != nil {
		logger.WebLog.Debugf(ctx, "[%s] 用户 [%s] 登录失败 Session错误:%s", ip, r.Username, err.Error())
		return returnErr
	}
	logger.WebLog.Debugf(ctx, "[%s] 用户 [%s] 登录成功", ip, r.Username)
	s.saveLoginLog(ctx, r.Username, ip, userAgent)
	Context.SetUser(ctx, &model.ContextUser{
		Id:       user.Id,
		UserName: user.Username,
		Email:    user.Email,
	})
	return nil
}

func (s *serviceUser) checkPassword(password, newPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(password), []byte(newPassword))
	return err == nil
}

func (s *serviceUser) IsSignedIn(ctx context.Context) bool {
	c := Context.Get(ctx)
	return c != nil && c.User != nil
}

func TransToUser(one gdb.Record) (*model.Users, error) {
	var user *model.Users
	if err := one.Struct(&user); err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	return user, nil
}

func (s *serviceUser) saveLoginLog(ctx context.Context, username, ip, userAgent string) {
	if _, err := dao.UserLog.Ctx(ctx).Insert(g.Map{"username": username, "ip": ip, "user_agent": userAgent}); err != nil {
		logger.WebLog.Warningf(ctx, "保存登录日志出现错误:%s", err.Error())
	}
}
