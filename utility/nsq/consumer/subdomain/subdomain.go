package subdomain

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/Rewriterl/ifgather/internal/dao"
	"github.com/Rewriterl/ifgather/internal/model"
	"github.com/Rewriterl/ifgather/utility/ipquery"
	"github.com/Rewriterl/ifgather/utility/logger"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/encoding/gbase64"
	"github.com/gogf/gf/v2/frame/g"
	"strings"
	"time"

	Gnsq "github.com/Rewriterl/ifgather/utility/nsq"
	"github.com/nsqio/go-nsq"
)

// Handler 子域名扫描 消费者类型
type Handler struct {
	Title string
}

// InitConsumer 子域名扫描 初始化消费者
func InitConsumer(ctx context.Context, topic string, channel string) {
	config := nsq.NewConfig()
	config.MsgTimeout = 10 * time.Minute
	if err := config.Validate(); err != nil {
		logger.WebLog.Fatalf(ctx, "[-] [子域名消费者] 配置文件错误:%s", err.Error())
	}
	consumer, err := nsq.NewConsumer(topic, channel, config)
	if err != nil {
		logger.WebLog.Fatalf(ctx, "[-] [子域名消费者] 创建消费者任务队列失败:%s", err.Error())
	}
	client := &Handler{
		Title: "server",
	}
	consumer.AddHandler(client)
	if err1 := consumer.ConnectToNSQD(g.Cfg().MustGet(ctx, "nsq.tcpHost").String()); err1 != nil {
		logger.WebLog.Fatalf(ctx, "[-] [子域名消费者] 连接任务队列服务器失败:%s", err1.Error())
	}
	logger.WebLog.Infof(ctx, "[+] [子域名消费者] 连接任务队列服务器成功")
}

// HandleMessage 子域名扫描 接受nsqd消息
func (m *Handler) HandleMessage(msg *nsq.Message) error {
	if len(msg.Body) == 0 {
		return nil
	}
	var DomainInfo []Gnsq.ResponseSubDomainStruct
	ctx := context.Background()
	msgStr, err := gbase64.Decode(msg.Body)
	if err != nil {
		logger.WebLog.Warningf(ctx, "[-] [子域名扫描消费者] Base64解码消息失败:%s", err.Error())
		return nil
	}
	if err = json.Unmarshal(msgStr, &DomainInfo); err != nil {
		logger.WebLog.Warningf(ctx, "[-] [子域名扫描消费者] Json反序列化失败:%s", err.Error())
		return nil
	}
	if len(DomainInfo) == 0 {
		logger.WebLog.Warningf(ctx, "[-] [子域名扫描消费者] 解码后无数据")
		return nil
	}
	if strings.Contains(DomainInfo[0].CusName, "util-") {
		return pushUtilSubDomain(ctx, DomainInfo)
	}
	return pushSubDomain(ctx, DomainInfo)
}

// subDomainPush 处理子域名结果
func pushSubDomain(ctx context.Context, r []Gnsq.ResponseSubDomainStruct) error {
	time.Sleep(2 * time.Second)
	res, err := dao.ScanDomain.Ctx(ctx).Where("domain=? AND nsq_flag=?", r[0].Domain, true).One()
	sd, _ := TransToScanDomain(res)
	if err != nil {
		logger.WebLog.Warningf(ctx, "[-] [子域名扫描] 查询主域名扫描状态失败:%s", err.Error())
		return err
	}
	if !sd.Flag {
		_, err1 := dao.ScanDomain.Ctx(ctx).Where("domain=? AND nsq_flag=?", r[0].Domain, true).Update(g.Map{"flag": true}) // 更改主域名扫描状态
		if err1 != nil {
			logger.WebLog.Warningf(ctx, "[-] [子域名扫描] 更改主域名扫描状态失败:%s", err.Error())
			return err1
		}
	}

	if len(r) == 1 { // 处理没有结果的
		if r[0].Subdomain == "null" {
			logger.WebLog.Debugf(ctx, "[-] [子域名扫描] [%s]主域名未发现子域名", r[0].Domain)
			return nil
		}
	}
	subdomainCount, err := dao.ScanSubdomain.Ctx(ctx).Where("subdomain=?", r[0].Subdomain).Count()
	if err != nil {
		logger.WebLog.Warningf(ctx, "[-] [子域名扫描] 查询子域名数据库错误:%s", err.Error())
		return err
	}
	if subdomainCount != 0 {
		logger.WebLog.Warningf(ctx, "[-] [子域名扫描] [%s]子域名已存在，发现重复子域名扫描数据", r[0].Subdomain)
		return nil
	}
	Ips := make(map[string]string, 0) // 建立map 减少ip查询
	for i := 0; i < len(r); i++ {
		if !strings.Contains(r[i].Ip, ",") {
			if v, ok := Ips[r[i].Ip]; ok {
				r[i].Location = v
				continue
			}
			ipinfo, err := ipquery.QueryIp(r[i].Ip)
			if err != nil {
				continue
			}
			Ips[r[i].Ip] = r[i].Ip
			r[i].Location = ipquery.QueryLocation(ipinfo)
		}
	}
	if _, err = dao.ScanSubdomain.Ctx(ctx).Insert(r); err != nil { // 批量插入
		logger.WebLog.Warningf(ctx, "[-] [子域名扫描] 保存结果失败:%s", err.Error())
		return nil
	}
	return nil
}

// pushUtilSubDomain 处理子域名结果
func pushUtilSubDomain(ctx context.Context, r []Gnsq.ResponseSubDomainStruct) error {
	time.Sleep(2 * time.Second)
	CusName := r[0].CusName
	CusName = strings.Replace(CusName, "util-", "", -1)
	res, err := dao.UtilSubdomainTask.Ctx(ctx).Where("cus_name=?", CusName).One()
	if err != nil {
		logger.WebLog.Warningf(ctx, "[-] [Util-子域名扫描消费者] 数据库查询对应任务名失败：%s", err.Error())
		return err
	}
	if res == nil {
		return nil
	}
	domain, _ := TransToUtilScanDomain(res)
	if domain.ScanNum < domain.DomainNum {
		if _, err = dao.UtilSubdomainTask.Ctx(ctx).Update(g.Map{"scan_num": domain.ScanNum + 1}, "cus_name", CusName); err != nil {
			logger.WebLog.Warningf(ctx, "[-] [Util-子域名扫描消费者] 修改已扫描数失败:%s", err.Error())
		}
	}
	if len(r) == 1 { // 处理没有结果的
		if r[0].Subdomain == "null" {
			return nil
		}
	}
	Ips := make(map[string]string, 0) // 建立map 减少ip查询
	for i := 0; i < len(r); i++ {
		r[i].CusName = strings.Replace(r[i].CusName, "util-", "", -1)
		if !strings.Contains(r[i].Ip, ",") {
			if v, ok := Ips[r[i].Ip]; ok {
				r[i].Location = v
				continue
			}
			ipinfo, err := ipquery.QueryIp(r[i].Ip)
			if err != nil {
				continue
			}
			Ips[r[i].Ip] = r[i].Ip
			r[i].Location = ipquery.QueryLocation(ipinfo)
		}
	}
	if _, err = dao.UtilSubdomainResult.Ctx(ctx).Insert(r); err != nil { // 批量插入
		logger.WebLog.Warningf(ctx, "[-] [Util-子域名扫描消费者] 保存结果失败:%s", err.Error())
		return nil
	}
	return nil
}
func TransToScanDomain(one gdb.Record) (*model.ScanDomain, error) {
	var scanDomain *model.ScanDomain
	if err := one.Struct(&scanDomain); err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	return scanDomain, nil
}

func TransToUtilScanDomain(one gdb.Record) (*model.UtilSubdomainTask, error) {
	var task *model.UtilSubdomainTask
	if err := one.Struct(&task); err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	return task, nil
}
