package logger

import "github.com/gogf/gf/v2/os/glog"

var WebLog *glog.Logger

func InitLogs() {
	logs := glog.New()
	err := logs.SetPath("logs")
	if err != nil {
		return
	}
	err1 := logs.SetLevelStr("all")
	if err1 != nil {
		return
	}
	WebLog = logs
}
