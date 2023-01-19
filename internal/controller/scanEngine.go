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

// SetNsqEngine 扫描引擎 添加消息队列配置
func (a *apiScan) SetNsqEngine(r *ghttp.Request) {
	var (
		data *model.APIKeyEngineNsqReq
	)
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.ScanEngine.SetNsqEngine(r.Context(), data); err != nil {
		response.JsonExit(r, 201, err.Error())
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "扫描引擎", fmt.Sprintf("修改消息队列[%s]", data.NsqHost))
		response.JsonExit(r, 200, "ok")
	}
}

// SetPortScanEngine 扫描引擎 添加端口扫描配置
func (a *apiScan) SetPortScanEngine(r *ghttp.Request) {
	var (
		data *model.ApiKeyEnginePortScanReq
	)
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.ScanEngine.SetPortScanEngine(r.Context(), data); err != nil {
		response.JsonExit(r, 201, err.Error())
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "扫描引擎", "修改端口扫描参数")
		response.JsonExit(r, 200, "ok")
	}
}

// SetDomainEngine 扫描引擎 添加子域名
func (a *apiScan) SetDomainEngine(r *ghttp.Request) {
	var (
		data *model.ApiKeyEngineDomainReq
	)
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.ScanEngine.SetDomainEngine(r.Context(), data); err != nil {
		response.JsonExit(r, 201, err.Error())
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "扫描引擎", "修改子域名扫描参数")
		response.JsonExit(r, 200, "ok")
	}
}

// SetApiKeyEngine 扫描引擎 添加API秘钥
func (a *apiScan) SetApiKeyEngine(r *ghttp.Request) {
	var (
		data *model.ApiKeyEngineKeyReq
	)
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.ScanEngine.SetApiKeyEngine(r.Context(), data); err != nil {
		response.JsonExit(r, 201, err.Error())
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "扫描引擎", "修改API秘钥参数")
		response.JsonExit(r, 200, "ok")
	}
}

// SetWebInfoEngine 扫描引擎 添加Web探测
func (a *apiScan) SetWebInfoEngine(r *ghttp.Request) {
	var (
		data *model.ApiKeyEngineWebInfoReq
	)
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.ScanEngine.SetWebInfoEngine(r.Context(), data); err != nil {
		response.JsonExit(r, 201, err.Error())
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "扫描引擎", "修改Web探测参数")
		response.JsonExit(r, 200, "ok")
	}
}
