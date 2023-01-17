package pushmsg

import (
	"context"
	"github.com/Rewriterl/ifgather/internal/dao"
	"github.com/Rewriterl/ifgather/internal/model"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
)

func TimingPush(ctx context.Context) {
	ReadNsqConfig(ctx)
}

func ReadNsqConfig(ctx context.Context) {
	var nsqConfig model.APIKeyEngineNsqReq
	c, _ := g.Cfg().Get(ctx, "nsq.tcpHost")
	nsqConfig.NsqHost = c.String()
	c, _ = g.Cfg().Get(ctx, "nsq.tcpPort")
	nsqConfig.NsqHttp = c.String()
	nsqConfig.Time = 999
	count, err := dao.ApiKey.Ctx(ctx).Where("key = ?", "engine_nsq").Count()
	if err != nil {
		return
	}
	if count == 0 {
		jsonString, err := gjson.New(nsqConfig).ToJsonString()
		if err != nil {
			_, _ = dao.ApiKey.Ctx(ctx).Insert(g.Map{"key": "engine_nsq", "value": jsonString})
		}
	}
}
