package controller

import (
	"fmt"
	"github.com/Rewriterl/ifgather/internal/model"
	"github.com/Rewriterl/ifgather/internal/service"
	"github.com/Rewriterl/ifgather/utility/response"
	"github.com/gogf/gf/v2/net/ghttp"
)

var Scan = new(apiScan)

type apiScan struct{}

func (a *apiScan) SetAPIKeyEngineNsq(r *ghttp.Request) {
	var (
		data *model.APIKeyEngineNsqReq
	)
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.ScanEngine.SetAPIKeyEngineNsq(r.Context(), data); err != nil {
		response.JsonExit(r, 201, err.Error())
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "扫描引擎", fmt.Sprintf("修改消息队列[%s]", data.NsqHost))
		response.JsonExit(r, 200, "ok")
	}
}
