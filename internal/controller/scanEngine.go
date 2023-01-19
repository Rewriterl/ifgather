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

// SetAPIKeyEngineNsq 扫描引擎 添加消息队列配置
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

// SetApiKeyEnginePortScan 扫描引擎 添加端口扫描配置
func (a *apiScan) SetApiKeyEnginePortScan(r *ghttp.Request) {
	var (
		data *model.ApiKeyEnginePortScanReq
	)
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.ScanEngine.SetApiKeyEnginePortScan(r.Context(), data); err != nil {
		response.JsonExit(r, 201, err.Error())
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "扫描引擎", "修改端口扫描参数")
		response.JsonExit(r, 200, "ok")
	}
}

// SetApiKeyEngineDomain 扫描引擎 添加子域名
func (a *apiScan) SetApiKeyEngineDomain(r *ghttp.Request) {
	var (
		data *model.ApiKeyEngineDomainReq
	)
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.ScanEngine.SetApiKeyEngineDomain(r.Context(), data); err != nil {
		response.JsonExit(r, 201, err.Error())
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "扫描引擎", "修改子域名扫描参数")
		response.JsonExit(r, 200, "ok")
	}
}
