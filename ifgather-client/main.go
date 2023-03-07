package main

import (
	"context"
	_ "github.com/Rewriterl/ifgather-client/utility/config"
	_ "github.com/Rewriterl/ifgather-client/utility/logger"
	Gnsq "github.com/Rewriterl/ifgather-client/utility/nsq"
	"github.com/Rewriterl/ifgather-client/utility/nsq/webInfo"
	"github.com/gogf/gf/v2/frame/g"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	get, _ := g.Cfg().Get(context.Background(), "webinfo.enabled")
	if get.Bool() {
		log.Println("[+] web探测模块开启")
		webInfo.InitConsumer(Gnsq.WebInfoTopic, Gnsq.WebInfoChanl)
	}
	c := make(chan os.Signal)        // 定义一个信号的通道
	signal.Notify(c, syscall.SIGINT) // 转发键盘中断信号到c
	<-c                              // 阻塞
}
