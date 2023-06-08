package pushmsg

import (
	"context"
	"github.com/Rewriterl/ifgather-server/internal/dao"
	"github.com/Rewriterl/ifgather-server/internal/model"
	"github.com/Rewriterl/ifgather-server/utility/logger"
	"github.com/Rewriterl/ifgather-server/utility/nsq/producer"
	"github.com/Rewriterl/ifgather-server/utility/tools"
	"github.com/gogf/gf/v2/container/gset"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"time"
)

func TimingPush(ctx context.Context) {
	ReadNsqConfig(ctx)
	for {
		PushPortScan(ctx)
		pushWebInfo(ctx)
		pushWebInfoCdn(ctx)
		time.Sleep(30 * time.Second)
	}
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
	err = tools.TransToStructs(all, &scanDomains)
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

// PushPortScan 投递端口扫描
func PushPortScan(ctx context.Context) {
	all, err := dao.ScanSubdomain.Ctx(ctx).Where("flag=? and nsq_flag=? and cdn=? and ip<>?", false, false, false, "null").All()
	if err != nil {
		logger.WebLog.Warningf(ctx, "[-] [投递端口扫描] 获取端口扫描数据失败:%s", err.Error())
		return
	}
	var scanSubDomains []*model.ScanSubdomain
	err = tools.TransToStructs(all, &scanSubDomains)
	if all == nil || len(all) == 0 {
		return
	}
	iplist := gset.NewStrSet() // IP去重
	pullresult := make([]model.UtilPortScanApiAddReq, 0)
	for _, v := range scanSubDomains {
		if iplist.ContainsI(v.Ip) {
			continue
		}
		iplist.Add(v.Ip)
		pullresult = append(pullresult, model.UtilPortScanApiAddReq{
			CusName: v.CusName,
			Hosts:   v.Ip,
		})
	}
	_, err = dao.ScanSubdomain.Ctx(ctx).Where("flag=? and nsq_flag=? and cdn=? and ip<>?", false, false, false, "null").Update(g.Map{"nsq_flag": true}) // 更新投递状态
	if err != nil {
		logger.WebLog.Warningf(ctx, "[-] [投递端口扫描] 更新子域名投递状态失败:%s", err.Error())
		return
	}
	producer.SendPortScanMessage(ctx, pullresult)
}

func pushWebInfo(ctx context.Context) {
	all, err := dao.ScanPort.Ctx(ctx).Where("flag=? and nsq_flag=? and http_flag=?", false, false, true).All()
	if err != nil {
		logger.WebLog.Warningf(ctx, "[-] [投递Web探测] 获取所需扫描数据失败:%s", err.Error())
		return
	}
	if all == nil || len(all) == 0 {
		return
	}
	var scanPorts []*model.ScanPort
	err = tools.TransToStructs(all, &scanPorts)
	pullMsgs := make([]model.NsqPushWeb, 0)
	for _, v := range scanPorts {
		res, err := dao.ScanSubdomain.Ctx(ctx).Where("ip=?", v.Host).All()
		if err != nil {
			logger.WebLog.Warningf(ctx, "[-] [投递Web探测] 查找子域名数据库错误:%s", err.Error())
			return
		}
		var scanSubDomains []*model.ScanSubdomain
		err = tools.TransToStructs(res, scanSubDomains)
		subdomains := make([]string, 0)
		for i, v1 := range scanSubDomains {
			if i > 100 {
				break
			}
			subdomains = append(subdomains, v1.Subdomain)
		}
		if len(subdomains) == 0 {
			continue
		}
		pullMsgs = append(pullMsgs, model.NsqPushWeb{
			CusName:     v.CusName,
			SubDomain:   subdomains,
			ServiceName: v.ServiceName,
			Port:        v.Port,
			Ip:          v.Host,
		})
	}
	if len(pullMsgs) == 0 {
		return
	}
	_, err = dao.ScanPort.Ctx(ctx).Where("flag=? and nsq_flag=? and http_flag=?", false, false, true).Update(g.Map{"nsq_flag": true}) // 更新投递状态
	if err != nil {
		logger.WebLog.Warningf(ctx, "[-] [投递Web探测] 更新端口投递状态失败:%s", err.Error())
		return
	}
	producer.PushWebInfo(ctx, pullMsgs)
}

// pushWebInfoCdn 投递CDN web探测
func pushWebInfoCdn(ctx context.Context) {
	all, err := dao.ScanSubdomain.Ctx(ctx).Where("flag=? and nsq_flag=? and cdn=?", false, false, true).All()
	if err != nil {
		logger.WebLog.Warningf(ctx, "[-] [投递Web探测CDN] 获取所需扫描数据失败:%s", err.Error())
		return
	}
	if all == nil || len(all) == 0 {
		return
	}
	var scanSubDomains []*model.ScanSubdomain
	err = tools.TransToStructs(all, &scanSubDomains)
	pullMsgs := make([]model.NsqPushWeb, 0)
	for _, v := range scanSubDomains {
		pullMsgs = append(pullMsgs, model.NsqPushWeb{
			CusName:     "CDN" + v.CusName,
			SubDomain:   []string{v.Subdomain},
			ServiceName: "http",
			Port:        80,
			Ip:          v.Ip,
		})
	}
	if len(pullMsgs) == 0 {
		return
	}
	_, err = dao.ScanSubdomain.Ctx(ctx).Where("flag=? and nsq_flag=? and cdn=?", false, false, true).Update(g.Map{"nsq_flag": true})
	if err != nil {
		logger.WebLog.Warningf(ctx, "[-] [投递Web探测CDN] 更新子域名投递状态失败:%s", err.Error())
		return
	}
	producer.PushWebInfo(ctx, pullMsgs)
}

//// webScreenshot web截图
//func webScreenshot(Url string)(string, error){
//	filename := gfile.Join("public/screenshot", gtime.TimestampMicroStr()+".png")
//	s1 := screenshot.Config{
//		Timeout: 10,
//		Url: Url,
//		FileName: filename,
//	}
//	err := s1.Run()
//	if err != nil{
//		logger.WebLog.Warningf(context.Background(), "[-] web截图失败:%s", err.Error())
//		return "",err
//	}
//	return filename,nil
//}
//
//// TimingWebScreenshot
//func TimingWebScreenshot(){
//	ctx := context.Background()
//	for{
//		time.Sleep(2*time.Second)
//		result,err := dao.ScanWeb.Ctx(ctx).Where("screenshot_flag=?",false).One()
//		if err != nil{
//			logger.WebLog.Warningf(ctx,"[-] web截图查询数据库失败:%s", err.Error())
//			continue
//		}
//		var scanWeb model.ScanWeb
//		err = tools.TransToStruct(result, &scanWeb)
//		if result == nil{
//			time.Sleep(1*time.Minute)
//			continue
//		}
//		filename, err := webScreenshot(scanWeb.Url)
//		if err != nil{
//			continue
//		}
//		if _,err = dao.ScanWeb.Ctx(ctx).Update(g.Map{"screenshot_flag": true,"image":filename},"url",result.Url); err != nil{
//			logger.WebLog.Warningf(ctx,"[-] web截图更新状态失败:%s", err.Error())
//		}
//	}
//}
