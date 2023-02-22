package response

import "github.com/gogf/gf/v2/net/ghttp"

type JsonResponse struct {
	Code    int         `json:"code"` // 错误码((0:成功, 1:失败, >1:错误码))
	Message string      `json:"msg"`  // 提示信息
	Data    interface{} `json:"data"` // 返回数据(业务接口定义具体数据结构)
}

func Json(r *ghttp.Request, code int, message string, data ...interface{}) {
	responseData := interface{}(nil)
	if len(data) > 0 {
		responseData = data[0]
	}
	r.Response.WriteJson(JsonResponse{
		Code:    code,
		Message: message,
		Data:    responseData,
	})
}

func JsonExit(r *ghttp.Request, err int, msg string, data ...interface{}) {
	Json(r, err, msg, data...)
	r.Exit()
}
