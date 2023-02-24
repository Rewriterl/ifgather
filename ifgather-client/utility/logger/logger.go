package logger

import (
	"context"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/glog"
)

var Log *glog.Logger
var LogPortScan *glog.Logger
var LogDomain *glog.Logger
var LogWebInfo *glog.Logger

func init() {
	ctx := context.Background()
	LogPortScan = glog.New()
	_ = LogPortScan.SetConfigWithMap(g.Map{
		"path":   "logs",
		"level":  g.Cfg().MustGet(ctx, "portscan.level"),
		"file":   "portscan-{Y-m-d}.log",
		"prefix": "端口扫描",
	})

	Log = glog.New()
	_ = Log.SetConfigWithMap(g.Map{
		"path":   "logs",
		"level":  "all",
		"file":   "client-{Y-m-d}.log",
		"prefix": "GoScan",
	})

	LogDomain = glog.New()
	_ = LogDomain.SetConfigWithMap(g.Map{
		"path":   "logs",
		"level":  g.Cfg().MustGet(ctx, "domain.level"),
		"file":   "domain-{Y-m-d}.log",
		"prefix": "子域名扫描",
	})

	LogWebInfo = glog.New()
	_ = LogWebInfo.SetConfigWithMap(g.Map{
		"path":   "logs",
		"level":  g.Cfg().MustGet(ctx, "webinfo.level"),
		"file":   "web-{Y-m-d}.log",
		"prefix": "web探测",
	})
}
