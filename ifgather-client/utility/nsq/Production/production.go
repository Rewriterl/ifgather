package Production

import (
	"context"
	"errors"
	"fmt"
	"github.com/gogf/gf/v2/encoding/gbase64"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"strings"

	"github.com/Rewriterl/ifgather-client/utility/config"
)

// 往topic中投递消息
func SendTopicMessages(topicName string, data interface{}) error {
	sendStr, err := gjson.New(data).ToJsonString()
	if err != nil {
		return err
	}
	msgStr := gbase64.EncodeString(sendStr)
	Url := fmt.Sprintf("http://%s/pub?topic=%s", config.Gconf.Nsq.NsqHttp, topicName)
	resp, err := g.Client().Post(context.Background(), Url, msgStr)
	defer func() {
		if resp != nil {
			resp.Close()
		}
	}()
	if err != nil {
		return err
	}
	if strings.Contains(resp.ReadAllString(), "OK") {
		return nil
	} else {
		return errors.New(fmt.Sprintf("Push 消息失败:%s", resp.ReadAllString()))
	}
}
