package tools

import (
	"context"
	"database/sql"
	"github.com/Rewriterl/ifgather-server/internal/model"
	"github.com/Rewriterl/ifgather-server/utility/nsq/producer"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/os/gfile"
	"time"
)

type ScanDomain struct {
	Domain string `v:"domain#主域名不正确"`
}

func TransToStruct(one gdb.Record, out interface{}) error {
	if err := one.Struct(out); err != nil && err != sql.ErrNoRows {
		return err
	}
	return nil
}

func TransToStructs(all gdb.Result, out interface{}) error {
	if err := all.Structs(out); err != nil && err != sql.ErrNoRows {
		return err
	}
	return nil
}

func GetNsqResInfo(ctx context.Context, topic string, channel string) *model.NsqResInfo {
	jsondata, err := producer.NsqStatsInfo(ctx, topic)
	if err != nil {
		return &model.NsqResInfo{Code: 0, Msg: "获取消息队列信息失败", Count: 0, Data: nil}
	}
	message_count := 0  // 消息总数
	message_bytes := "" // 消息大小
	client_count := 0   // 客户端数
	timeout_count := 0  // 超时数
	result := make([]model.NsqResInfos, 0)
	for _, v := range jsondata.Topics {
		message_count = v.MessageCount
		message_bytes = gfile.FormatSize(v.MessageBytes)
		for _, k := range v.Channels {
			if k.ChannelName == channel {
				client_count = k.ClientCount
				timeout_count = k.TimeoutCount
				for _, y := range k.Clients {
					result = append(result, model.NsqResInfos{
						Hostname:      y.Hostname,      // 客户端主机名
						RemoteAddress: y.RemoteAddress, // 客户端地址
						MessageCount:  y.MessageCount,  // 客户端消息数
						FinishCount:   y.FinishCount,   // 客户端完成数
						ConnectTs:     time.Unix(y.ConnectTs, 0).Format("2006-01-02 15:04:05"),
					})
				}
				break // 找到chanl就跳出循环
			}
		}
	}
	if len(result) == 0 {
		return &model.NsqResInfo{Code: 0, Msg: "无客户端", Count: 0, Data: nil, MessageCount: message_count,
			MessageBytes: message_bytes, TimeoutCount: timeout_count, ClientCount: client_count}
	}
	return &model.NsqResInfo{Code: 0, Msg: "ok", Count: 0, Data: result, MessageCount: message_count,
		MessageBytes: message_bytes, TimeoutCount: timeout_count, ClientCount: client_count}
}
