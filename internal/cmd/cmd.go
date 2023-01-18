package cmd

import (
	"context"
	"crypto/rand"
	"github.com/Rewriterl/ifgather/internal/dao"
	"github.com/Rewriterl/ifgather/internal/model"
	"github.com/Rewriterl/ifgather/utility/logger"
	Gnsq "github.com/Rewriterl/ifgather/utility/nsq"
	"github.com/Rewriterl/ifgather/utility/nsq/consumer/portscan"
	"github.com/Rewriterl/ifgather/utility/nsq/consumer/subdomain"
	"github.com/Rewriterl/ifgather/utility/nsq/consumer/webinfo"
	"github.com/Rewriterl/ifgather/utility/nsq/producer"
	"github.com/Rewriterl/ifgather/utility/nsq/pushmsg"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gcmd"
	"golang.org/x/crypto/bcrypt"
	"time"
)

var (
	Main = gcmd.Command{
		Name:  "main",
		Usage: "main",
		Brief: "start http server",
		Func: func(ctx context.Context, parser *gcmd.Parser) (err error) {
			logger.InitLogs()
			producer.InitNsqProducer(ctx)
			subdomain.InitConsumer(ctx, Gnsq.RSubDomainTopic, Gnsq.RSubDomainChanl)
			portscan.InitConsumer(ctx, Gnsq.RPortScanTopic, Gnsq.RPortScanChanl)
			webinfo.InitConsumer(ctx, Gnsq.RWebInfoTopic, Gnsq.RWebInfoChanl)
			createAdmin(ctx)
			go pushmsg.TimingPush(ctx)
			s := g.Server()
			if err := s.SetConfigWithMap(g.Map{
				"serverAgent":         "ifGather",
				"SessionMaxAge":       300 * time.Minute,
				"SessionIdName":       "ifgather",
				"SessionCookieOutput": true,
			}); err != nil {
				logger.WebLog.Fatalf(ctx, "web服务器配置有误，程序运行失败:%s", err.Error())
			}
			s.Run()
			return nil
		},
	}
)

func createAdmin(ctx context.Context) {
	if i, err := dao.Users.Ctx(ctx).Count("username=?", "admin"); err != nil {
		logger.WebLog.Warningf(ctx, "[创建默认账户] 查询数据库错误:%s", err.Error())
		return
	} else if i != 0 {
		return
	} else {
		password := GeneratePassword(6, true, true, true, true)
		passwd, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			logger.WebLog.Warningf(ctx, "[创建默认账户] 加密密码错误:%s", err.Error())
			return
		} else {
			users := model.UsersApiRegisterReq{}
			users.Username = "admin"
			users.Password = string(passwd)
			users.NickName = "管理员"
			users.Email = "admin@qq.com"
			users.Phone = "13888888888"
			users.Remark = "管理员账户"
			if _, err := dao.Users.Ctx(ctx).Insert(users); err != nil {
				logger.WebLog.Warningf(ctx, "[创建默认账户] 数据库错误:%s", err.Error())
				return
			} else {
				logger.WebLog.Warningf(ctx, "[创建默认账户成功] 用户名:admin 密码:%s", password)
			}
		}
	}
}

func GeneratePassword(length int, includeUpper, includeLower, includeNumber, includeSpecial bool) string {
	// 定义字符集
	var charSet string
	if includeUpper {
		charSet += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if includeLower {
		charSet += "abcdefghijklmnopqrstuvwxyz"
	}
	if includeNumber {
		charSet += "0123456789"
	}
	if includeSpecial {
		charSet += "!@#$%^&*()"
	}

	var password []byte
	for i := 0; i < length; i++ {
		b := make([]byte, 1)
		_, _ = rand.Read(b)
		password = append(password, charSet[int(b[0])%len(charSet)])
	}
	password = append(password, '@', '1', 'f')
	return string(password)
}
