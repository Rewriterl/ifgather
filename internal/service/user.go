package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/Rewriterl/ifgather/internal/dao"
	"github.com/Rewriterl/ifgather/internal/model"
	"github.com/Rewriterl/ifgather/utility/logger"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/encoding/ghtml"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/util/gconv"
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

func (s *serviceUser) UserInfo(ctx context.Context) *model.Users {
	user := Session.GetUser(ctx)
	one, err := dao.Users.Ctx(ctx).One("username=?", user.Username)
	if err != nil {
		logger.WebLog.Warningf(ctx, "获取用户资料 数据库错误:%s", err.Error())
		return &model.Users{}
	}
	user1, err := TransToUser(one)
	user1.Password = "********"
	return user1
}

func (s *serviceUser) Logout(ctx context.Context) error {
	return Session.RemoveUser(ctx)
}

func (s *serviceUser) AddUserOptLog(ctx context.Context, ip, Theme, Content string) {
	_, err := dao.UserOperation.Ctx(ctx).Insert(g.Map{
		"Username": Session.GetUser(ctx).Username,
		"Ip":       ip,
		"Theme":    Theme,
		"Content":  Content,
	})
	if err != nil {
		logger.WebLog.Errorf(ctx, "保存日志出错 %s", err.Error())
		return
	}
	logger.WebLog.Infof(ctx, "用户操作 %s %s", Theme, Content)
}

func (s *serviceUser) SearchUser(ctx context.Context, page, limit int, search interface{}) *model.UserRspManager {
	var resultUser []*model.Users
	UserSearch := dao.Users.Ctx(ctx).Clone()
	searchStr := gconv.String(search)
	if search != "" {
		j := gjson.New(searchStr)
		if gconv.String(j.Get("username")) != "" {
			UserSearch = UserSearch.Where("username like ?", "%"+gconv.String(j.Get("username"))+"%")
		}
		if gconv.String(j.Get("phone")) != "" {
			UserSearch = UserSearch.Where("phone like ?", "%"+gconv.String(j.Get("phone"))+"%")
		}
		if gconv.String(j.Get("email")) != "" {
			UserSearch = UserSearch.Where("email like ?", "%"+gconv.String(j.Get("email"))+"%")
		}
		if gconv.String(j.Get("nickname")) != "" {
			UserSearch = UserSearch.Where("nick_name like ?", "%"+gconv.String(j.Get("nickname"))+"%")
		}
	}
	count, _ := UserSearch.Count()
	if page > 0 && limit > 0 {
		// BUG:查询结果中的id是以1为始的自增序列
		err := UserSearch.Order("id desc").Limit((page-1)*limit, limit).Scan(&resultUser)
		if err != nil {
			logger.WebLog.Warningf(ctx, "用户管理分页查询 数据库错误:%s", err.Error())
			return &model.UserRspManager{Code: 201, Msg: "查询失败,数据库错误", Count: 0, Data: nil}
		}
	} else {
		return &model.UserRspManager{Code: 201, Msg: "查询失败,分页参数有误", Count: 0, Data: nil}
	}
	index := (page - 1) * limit
	for i := range resultUser {
		resultUser[i].Password = ""
		index++
	}
	return &model.UserRspManager{Code: 0, Msg: "ok", Count: int64(count), Data: resultUser}
}

func (s *serviceUser) AddUser(ctx context.Context, r *model.UsersApiRegisterReq) error {
	if i, err := dao.Users.Ctx(ctx).Count("username=?", r.Username); err != nil {
		logger.WebLog.Warningf(ctx, "添加用户 数据库错误:%s", err.Error())
		return errors.New("添加用户失败")
	} else if i > 0 {
		return errors.New(fmt.Sprintf("账户 %s 已存在", r.Username))
	}
	encPassword, err := s.setPassword(r.Password)
	if err != nil {
		logger.WebLog.Warningf(ctx, "添加用户 密码加密失败:%s", err.Error())
		return errors.New("添加用户失败,加密密码错误")
	}
	r.Password = encPassword
	r.NickName = ghtml.SpecialChars(r.NickName)
	r.Remark = ghtml.SpecialChars(r.Remark)
	if _, err := dao.Users.Ctx(ctx).Insert(r); err != nil {
		logger.WebLog.Warningf(ctx, "添加用户 数据库错误:%s", err.Error())
		return errors.New("添加用户失败,数据库错误")
	}
	logger.WebLog.Warningf(ctx, "添加用户成功:%s", r.Username)
	return nil
}

func (s *serviceUser) setPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func (s *serviceUser) ChangePassword(ctx context.Context, r *model.UserApiChangePasswordReq) error {
	userinfo := Session.GetUser(ctx)
	one, err := dao.Users.Ctx(ctx).One("username=?", userinfo.Username)
	returnErr := errors.New("修改密码失败")
	if err != nil {
		logger.WebLog.Warningf(ctx, "修改密码 数据库错误:%s", err.Error())
		return returnErr
	}
	currentUser, _ := TransToUser(one)
	if !s.checkPassword(currentUser.Password, r.Password) {
		return returnErr
	}
	encPassword, err := s.setPassword(r.Password1)
	if err != nil {
		logger.WebLog.Warningf(ctx, "修改密码 加密密码错误:%s", err.Error())
		return returnErr
	}
	if result, err := dao.Users.Ctx(ctx).Update(g.Map{"password": encPassword}, "username", userinfo.Username); err != nil {
		logger.WebLog.Warningf(ctx, "修改密码 数据库错误:%s", err.Error())
		return returnErr
	} else if result != nil {
		return nil
	} else {
		return returnErr
	}
}

func (s *serviceUser) UserDel(ctx context.Context, r *model.UserApiDelReq) error {
	one, err2 := dao.Users.Ctx(ctx).One("id=?", r.Id)
	returnErr := errors.New("删除用户失败")
	if err2 != nil {
		logger.WebLog.Warning(ctx, "要删除的用户不存在")
		return returnErr
	}
	user, _ := TransToUser(one)
	if user.Username == "admin" {
		return errors.New("删除用户失败 不能删除admin账户")
	}
	result, err := dao.Users.Ctx(ctx).Delete("id=?", r.Id)
	if err != nil {
		logger.WebLog.Warningf(ctx, "删除用户 数据库错误:%s", err.Error())
		return returnErr
	}
	if result != nil {
		return nil
	} else {
		return returnErr
	}
}

func (s *serviceUser) IsAdmin(ctx context.Context) bool {
	userinfo := Session.GetUser(ctx)
	return userinfo.Username == "admin"
}
