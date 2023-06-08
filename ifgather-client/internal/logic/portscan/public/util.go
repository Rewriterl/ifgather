package public

import (
	"context"
	"github.com/Rewriterl/ifgather-client/utility/logger"
	"os"
	"runtime"
	"syscall"
)

// IsOSSupported 判断运行的系统环境
func IsOSSupported() bool {
	return runtime.GOOS == "linux" || runtime.GOOS == "darwin"
}

// IsRoot 判断用户权限
func IsRoot() bool {
	return os.Geteuid() == 0
}

// SetUlimit 设置系统ulimit值
func SetUlimit() {
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		logger.LogPortScan.Warningf(context.Background(), "获取系统ulimit值失败:%s", err.Error())
		return
	}
	logger.LogPortScan.Debugf(context.Background(), "当前系统ulimit为:Cur:%d Max:%d", rLimit.Max, rLimit.Cur)
	rLimit.Max = 999999
	rLimit.Cur = 999999
	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		logger.LogPortScan.Warningf(context.Background(), "设置系统ulimit值失败:%s", err.Error())
		return
	}
	err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		logger.LogPortScan.Warningf(context.Background(), "获取系统ulimit值失败:%s", err.Error())
		return
	}
	logger.LogPortScan.Debugf(context.Background(), "成功设置当前系统ulimit为:Cur:%d Max:%d", rLimit.Max, rLimit.Cur)
}
