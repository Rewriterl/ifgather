package portscan

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/Rewriterl/ifgather/internal/dao"
	"github.com/Rewriterl/ifgather/internal/model"
	"github.com/Rewriterl/ifgather/utility/logger"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/encoding/gbase64"
	"github.com/gogf/gf/v2/frame/g"
	"strings"
	"time"

	Gnsq "github.com/Rewriterl/ifgather/utility/nsq"

	"github.com/nsqio/go-nsq"
)

// PortScanHandler 端口扫描 消费者类型
type PortScanHandler struct {
	Title string
}

// InitConsumer 端口扫描 初始化消费者
func InitConsumer(ctx context.Context, topic string, channel string) {
	config := nsq.NewConfig()
	config.MsgTimeout = 10 * time.Minute
	if err := config.Validate(); err != nil {
		logger.WebLog.Fatalf(ctx, "[-] [端口扫描消费者] 配置文件错误:%s", err.Error())
	}
	consumer, err := nsq.NewConsumer(topic, channel, config)
	if err != nil && consumer == nil {
		logger.WebLog.Fatalf(ctx, "[-] [端口扫描消费者] 创建消费者消息队列失败:%s", err.Error())
	}
	client := &PortScanHandler{
		Title: "server",
	}
	consumer.AddHandler(client)
	cfg, _ := g.Cfg().Get(ctx, "nsq.tcpHost")
	if err1 := consumer.ConnectToNSQD(cfg.String()); err1 != nil {
		logger.WebLog.Fatalf(ctx, "[-] [端口扫描消费者] 连接消息队列服务失败:%s", err1.Error())
	}
	logger.WebLog.Infof(ctx, "[+] [端口扫描消费者] 连接消息队列服务成功")
}

// HandleMessage 端口扫描 接受nsqd消息
func (m *PortScanHandler) HandleMessage(msg *nsq.Message) error {
	if len(msg.Body) == 0 {
		return nil
	}
	var result []Gnsq.ResponsePortScanStruct
	msgStr, err := gbase64.Decode(msg.Body)
	ctx := context.Background()
	if err != nil {
		logger.WebLog.Warningf(ctx, "[-] [端口扫描消息消费者] Base64解码消息失败:%s", err.Error())
		return nil
	}
	if err = json.Unmarshal(msgStr, &result); err != nil {
		logger.WebLog.Warningf(ctx, "[-] [端口扫描消息消费者] Json反序列化失败:%s", err.Error())
		return nil
	}
	if len(result) == 0 {
		logger.WebLog.Warningf(ctx, "[-] [端口扫描消息消费者] 解码后无数据")
		return nil
	}
	if strings.Contains(result[0].CusName, "util-") {
		return utilPortScanPush(ctx, result)
	}
	return portScanPush(ctx, result)
}

// portScanPush 处理端口扫描结果
func portScanPush(ctx context.Context, r []Gnsq.ResponsePortScanStruct) error {
	time.Sleep(1 * time.Second)
	count, err := dao.ScanPort.Ctx(ctx).Where("host=?", r[0].Host).Count()
	if err != nil {
		logger.WebLog.Warningf(ctx, "[-] [端口扫描] 查询Host数据库错误:%s", err.Error())
		return err
	}
	if count != 0 {
		logger.WebLog.Warningf(ctx, "[-] [端口扫描] [%s] 发现重复Host", r[0].Host)
		return nil
	}
	_, err = dao.ScanSubdomain.Ctx(ctx).Where("ip=?", r[0].Host).Update(g.Map{"flag": true}) // 更改子域名扫描状态
	if err != nil {
		logger.WebLog.Warningf(ctx, "[-] [端口扫描] 更改子域名扫描状态失败:%s", err.Error())
		return err
	}
	if len(r) == 1 { // 处理没有结果的
		if r[0].ServiceName == "null" {
			return nil
		}
	}
	if _, err = dao.ScanPort.Ctx(ctx).Insert(r); err != nil { // 批量插入
		logger.WebLog.Warningf(ctx, "[-] [端口扫描] 保存结果失败:%s", err.Error())
		return nil
	}
	logger.WebLog.Debugf(ctx, "[+] [端口扫描] [%s]成功扫描到[%d]个端口", r[0].Host, len(r))
	return nil
}

// utilPortScanPush 处理端口扫描结果
func utilPortScanPush(ctx context.Context, r []Gnsq.ResponsePortScanStruct) error {
	time.Sleep(1 * time.Second)
	CusName := r[0].CusName
	CusName = strings.Replace(CusName, "util-", "", -1)
	res, err := dao.UtilPortscanTask.Ctx(ctx).Where("cus_name=?", CusName).One()
	if err != nil {
		logger.WebLog.Warningf(ctx, "[-] [Util-端口扫描结果处理消费者] 数据库查询对应任务名失败：%s", err.Error())
		return err
	}
	if res == nil {
		return nil
	}
	task, _ := TransToUPST(res)
	if _, err = dao.UtilPortscanTask.Ctx(ctx).Update(g.Map{"scan_num": task.ScanNum + 1}, "cus_name", CusName); err != nil {
		logger.WebLog.Warningf(ctx, "[-] [Util-端口扫描结果处理消费者] 修改已扫描数失败:%s", err.Error())
		return err
	}
	if len(r) == 1 { // 处理没有结果的
		if r[0].ServiceName == "null" {
			return nil
		}
	}
	for i, _ := range r {
		r[i].CusName = CusName
	}
	if _, err = dao.UtilPortscanResult.Ctx(ctx).Insert(r); err != nil { // 批量插入
		logger.WebLog.Warningf(ctx, "[-] [Util-端口扫描结果处理消费者] 保存结果失败:%s", err.Error())
		return nil
	}
	return nil
}

func TransToUPST(one gdb.Record) (*model.UtilPortscanTask, error) {
	var task *model.UtilPortscanTask
	if err := one.Struct(&task); err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	return task, nil
}
