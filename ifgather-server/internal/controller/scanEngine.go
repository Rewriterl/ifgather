package controller

import (
	"fmt"
	"github.com/Rewriterl/ifgather-server/internal/model"
	"github.com/Rewriterl/ifgather-server/internal/service"
	"github.com/Rewriterl/ifgather-server/utility/response"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/util/gconv"
)

var Scan = new(scanApi)

type scanApi struct{}

// SetNsqEngine 扫描引擎 添加消息队列配置
func (a *scanApi) SetNsqEngine(r *ghttp.Request) {
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
func (a *scanApi) SetPortScanEngine(r *ghttp.Request) {
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
func (a *scanApi) SetDomainEngine(r *ghttp.Request) {
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
func (a *scanApi) SetApiKeyEngine(r *ghttp.Request) {
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
func (a *scanApi) SetWebInfoEngine(r *ghttp.Request) {
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

func (a *scanApi) GetApiKeyEngine(r *ghttp.Request) {
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
		response.JsonExit(r, 200, "查询成功", service.ScanEngine.GetApiKeyEngine(r.Context()))
	} else {
		response.JsonExit(r, 201, "密码错误")
	}
}

// EmptyPort 端口扫描清空消息队列
func (a *scanApi) EmptyPort(r *ghttp.Request) {
	if err := service.ScanEngine.EmptyPort(r.Context()); err != nil {
		response.JsonExit(r, 201, "清空端口扫描任务队列失败")
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "端口扫描", "清空消息队列成功")
		response.JsonExit(r, 200, "ok")
	}
}

// EmptyDomain 子域名清空消息队列
func (a *scanApi) EmptyDomain(r *ghttp.Request) {
	if err := service.ScanEngine.EmptyDomain(r.Context()); err != nil {
		response.JsonExit(r, 201, "清空子域名扫描任务队列失败")
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "子域名扫描", "清空消息队列成功")
		response.JsonExit(r, 200, "ok")
	}
}

// EmptyWebInfo Web探测清空消息队列
func (a *scanApi) EmptyWebInfo(r *ghttp.Request) {
	if err := service.ScanEngine.EmptyWebInfo(r.Context()); err != nil {
		response.JsonExit(r, 201, "清空Web探测任务队列失败")
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "Web探测", "清空消息队列成功")
		response.JsonExit(r, 200, "ok")
	}
}

// ManagerAdd 添加厂商
func (a *scanApi) ManagerAdd(r *ghttp.Request) {
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
func (a *scanApi) ManagerDelete(r *ghttp.Request) {
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
func (a *scanApi) SearchManager(r *ghttp.Request) {
	r.Response.WriteJson(service.ScanEngine.SearchManager(r.Context(), r.Get("page").Int(), r.Get("limit").Int(), r.Get("searchParams")))
}

// AddDomain 添加主域名
func (a *scanApi) AddDomain(r *ghttp.Request) {
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
func (a *scanApi) SearchDomain(r *ghttp.Request) {
	r.Response.WriteJson(service.ScanEngine.SearchDomain(r.Context(), r.Get("page").Int(), r.Get("limit").Int(), r.Get("searchParams")))
}

// GetApiCusName 返回厂商数据
func (a *scanApi) GetApiCusName(r *ghttp.Request) {
	r.Response.WriteJson(service.ScanEngine.GetApiCusName(r.Context(), r.Get("page").Int(), r.Get("limit").Int(), r.Get("cusname")))
}

// SearchSubDomain 子域名模糊搜索分页查询
func (a *scanApi) SearchSubDomain(r *ghttp.Request) {
	r.Response.WriteJson(service.ScanEngine.SearchSubDomain(r.Context(), r.Get("page").Int(), r.Get("limit").Int(), r.Get("searchParams")))
}

// SearchPortScan 端口模糊搜索分页查询
func (a *scanApi) SearchPortScan(r *ghttp.Request) {
	r.Response.WriteJson(service.ScanEngine.SearchPortScan(r.Context(), r.Get("page").Int(), r.Get("limit").Int(), r.Get("searchParams")))
}

// SearchWebInfo Web信息模糊搜索分页查询
func (a *scanApi) SearchWebInfo(r *ghttp.Request) {
	r.Response.WriteJson(service.ScanEngine.SearchWebInfo(r.Context(), r.Get("page").Int(), r.Get("limit").Int(), r.Get("searchParams")))
}

// WebInfoTree 返回web爬虫结果
func (a *scanApi) WebInfoTree(r *ghttp.Request) {
	var data *model.ScanWebTreeReq
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	r.Response.WriteJson(service.ScanEngine.WebInfoTree(r.Context(), data))
}

// DelWebInfo 删除指定url
func (a *scanApi) DelWebInfo(r *ghttp.Request) {
	var data *model.ScanWebTreeReq
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.ScanEngine.DelWebInfo(r.Context(), data); err != nil {
		response.JsonExit(r, 201, err.Error())
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "删除web资产", fmt.Sprintf("Url[%s]", data.Url))
		response.JsonExit(r, 200, "ok")
	}
}

// NsqPortScanStat 端口扫描管理 Nsqd详情
func (a *scanApi) NsqPortScanStat(r *ghttp.Request) {
	r.Response.WriteJson(service.ScanEngine.NsqPortScanStat(r.Context()))
}

// NsqSubDomainStat 子域名扫描管理 Nsqd详情
func (a *scanApi) NsqSubDomainStat(r *ghttp.Request) {
	r.Response.WriteJson(service.ScanEngine.NsqSubDomainStat(r.Context()))
}

// NsqWebInfoStat Web信息扫描管理 Nsqd详情
func (a *scanApi) NsqWebInfoStat(r *ghttp.Request) {
	r.Response.WriteJson(service.ScanEngine.NsqWebInfoStat(r.Context()))
}
