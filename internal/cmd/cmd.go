package cmd

import (
	"context"
	"github.com/Rewriterl/ifgather/utility/logger"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gcmd"
	"time"
)

var (
	Main = gcmd.Command{
		Name:  "main",
		Usage: "main",
		Brief: "start http server",
		Func: func(ctx context.Context, parser *gcmd.Parser) (err error) {
			logger.InitLogs()
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
