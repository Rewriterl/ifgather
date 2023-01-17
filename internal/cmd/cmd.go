package cmd

import (
	"context"
	"github.com/Rewriterl/ifgather/utility/logger"
	Gnsq "github.com/Rewriterl/ifgather/utility/nsq"
	"github.com/Rewriterl/ifgather/utility/nsq/consumer/portscan"
	"github.com/Rewriterl/ifgather/utility/nsq/producer"
	"github.com/Rewriterl/ifgather/utility/nsq/pushmsg"
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
			producer.InitNsqProducer(ctx)
			portscan.InitConsumer(ctx, Gnsq.RSubDomainTopic, Gnsq.RSubDomainChanl)
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
