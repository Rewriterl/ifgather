package scan

import (
	"context"
	"fmt"
	"github.com/Rewriterl/ifgather-client/utility/logger"
	"net"
	"time"
)

// ConnectVerify 使用Connect方式二次校检Sync扫描出的端口
func ConnectVerify(host string, port int, timeout int) (bool, int) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), time.Duration(timeout)*time.Millisecond)
	if err != nil {
		return false, 0
	}
	defer conn.Close()
	logger.LogPortScan.Debugf(context.Background(), "[+] 二次验证 %s:%d 开放", host, port)
	return true, port
}
