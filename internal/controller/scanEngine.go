package controller

import (
	"fmt"
	"github.com/Rewriterl/ifgather/internal/model"
	"github.com/Rewriterl/ifgather/internal/service"
	"github.com/Rewriterl/ifgather/utility/response"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/util/gconv"
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

func (a *apiScan) GetApiKeyEngine(r *ghttp.Request) {
	pwd := gconv.String(r.Get("pwd"))
	if pwd == "" {
		response.JsonExit(r, 201, "请输入密码")
	}
	s, _ := g.Cfg().Get(r.Context(), "server.password")
	password := s.String()
	if password == "" {
		response.JsonExit(r, 201, "Web未配置同步密码")
	}
	if pwd == password {
		r.Response.WriteJson(service.ScanEngine.GetApiKeyEngine(r.Context()))
	} else {
		response.JsonExit(r, 201, "密码错误")
	}
}

// EmptyPort 端口扫描清空消息队列
func (a *apiScan) EmptyPort(r *ghttp.Request) {
	if err := service.ScanEngine.EmptyPort(r.Context()); err != nil {
		response.JsonExit(r, 201, "清空端口扫描任务队列失败")
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "端口扫描", "清空消息队列成功")
		response.JsonExit(r, 200, "ok")
	}
}

// EmptyDomain 子域名清空消息队列
func (a *apiScan) EmptyDomain(r *ghttp.Request) {
	if err := service.ScanEngine.EmptyDomain(r.Context()); err != nil {
		response.JsonExit(r, 201, "清空子域名扫描任务队列失败")
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "子域名扫描", "清空消息队列成功")
		response.JsonExit(r, 200, "ok")
	}
}

// EmptyWebInfo Web探测清空消息队列
func (a *apiScan) EmptyWebInfo(r *ghttp.Request) {
	if err := service.ScanEngine.EmptyWebInfo(r.Context()); err != nil {
		response.JsonExit(r, 201, "清空Web探测任务队列失败")
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "Web探测", "清空消息队列成功")
		response.JsonExit(r, 200, "ok")
	}
}

// ManagerAdd 添加厂商
func (a *apiScan) ManagerAdd(r *ghttp.Request) {
	var (
		data *model.ApiScanManagerAddReq
	)
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.ScanEngine.ManagerAdd(r.Context(), data); err != nil {
		response.JsonExit(r, 201, err.Error())
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "添加厂商", fmt.Sprintf("厂商名[%s]", data.CusName))
		response.JsonExit(r, 200, "ok")
	}
}

// ManagerDelete 删除厂商
func (a *apiScan) ManagerDelete(r *ghttp.Request) {
	var (
		data *model.ApiScanManagerDeleteReq
	)
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.ScanEngine.ManagerDelete(r.Context(), data); err != nil {
		response.JsonExit(r, 201, err.Error())
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "删除厂商", fmt.Sprintf("厂商名[%s]", data.CusName))
		response.JsonExit(r, 200, "ok")
	}
}

// SearchManager 厂商模糊搜索分页查询
func (a *apiScan) SearchManager(r *ghttp.Request) {
	r.Response.WriteJson(service.ScanEngine.SearchManager(r.Context(), r.Get("page").Int(), r.Get("limit").Int(), r.Get("searchParams")))
}

// AddDomain 添加主域名
func (a *apiScan) AddDomain(r *ghttp.Request) {
	var (
		data *model.ScanDomainApiAddReq
	)
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.ScanEngine.AddDomain(r.Context(), data); err != nil {
		response.JsonExit(r, 201, err.Error())
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "添加主域名", fmt.Sprintf("厂商名[%s]", data.CusName))
		response.JsonExit(r, 200, "ok")
	}
}

// SearchDomain 主域名模糊搜索分页查询
func (a *apiScan) SearchDomain(r *ghttp.Request) {
	r.Response.WriteJson(service.ScanEngine.SearchDomain(r.Context(), r.Get("page").Int(), r.Get("limit").Int(), r.Get("searchParams")))
}
