package controller

import (
	"fmt"
	"github.com/Rewriterl/ifgather/internal/model"
	"github.com/Rewriterl/ifgather/internal/service"
	"github.com/Rewriterl/ifgather/utility/response"
	"github.com/gogf/gf/v2/net/ghttp"
)

var Collector = new(collectorApi)

type collectorApi struct{}

// AddSubDomain 添加子域名扫描任务
func (a *collectorApi) AddSubDomain(r *ghttp.Request) {
	var (
		data *model.ScanDomainApiAddReq
	)
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.Collector.AddSubDomain(r.Context(), data); err != nil {
		response.JsonExit(r, 201, err.Error())
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "信息收集-添加子域名扫描任务", fmt.Sprintf("任务名[%s]", data.CusName))
		response.JsonExit(r, 200, "ok")
	}
}

// SearchSubDomainManager 模糊分页查询子域名
func (a *collectorApi) SearchSubDomainManager(r *ghttp.Request) {
	r.Response.WriteJson(service.Collector.SearchSubDomainManager(r.Context(), r.Get("page").Int(), r.Get("limit").Int(), r.Get("searchParams")))
}
