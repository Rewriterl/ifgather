package pushmsg

import (
	"context"
	"github.com/Rewriterl/ifgather/internal/dao"
	"github.com/Rewriterl/ifgather/internal/model"
	"github.com/Rewriterl/ifgather/utility/logger"
	"github.com/Rewriterl/ifgather/utility/nsq/producer"
	"github.com/Rewriterl/ifgather/utility/tools"
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

// PushDomain 投递子域名扫描
func PushDomain(ctx context.Context, cusName string) {
	all, err := dao.ScanDomain.Ctx(ctx).Where("cus_name=? AND nsq_flag=?", cusName, false).All()
	if err != nil {
		logger.WebLog.Warningf(ctx, "[-] 子域名投递消息  数据库查询错误:%s", err.Error())
		return
	}
	if all == nil || len(all) == 0 {
		return
	}
	pubMessages := make([]model.ScanDomainApiAddReq, 0)
	var scanDomains []*model.ScanDomain
	err = tools.TransToStructs(all, scanDomains)
	for _, v := range scanDomains {
		pubMessages = append(pubMessages, model.ScanDomainApiAddReq{CusName: v.CusName, Domain: v.Domain})
	}
	_, err = dao.ScanDomain.Ctx(ctx).Where("cus_name=? AND nsq_flag=?", cusName, false).Update(g.Map{"nsq_flag": true})
	if err != nil {
		logger.WebLog.Warningf(ctx, "[-] 子域名投递消息  修改主域名状态失败:%s", err.Error())
		return
	}
	producer.PushSubDomain(ctx, pubMessages)
}
