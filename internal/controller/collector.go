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

// AddSubDomainTask 添加子域名扫描任务
func (a *collectorApi) AddSubDomainTask(r *ghttp.Request) {
	var (
		data *model.ScanDomainApiAddReq
	)
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.Collector.AddSubDomainTask(r.Context(), data); err != nil {
		response.JsonExit(r, 201, err.Error())
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "信息收集-添加子域名扫描任务", fmt.Sprintf("任务名[%s]", data.CusName))
		response.JsonExit(r, 200, "ok")
	}
}

// SearchSubDomainTask 模糊分页查询子域名扫描任务
func (a *collectorApi) SearchSubDomainTask(r *ghttp.Request) {
	r.Response.WriteJson(service.Collector.SearchSubDomainTask(r.Context(), r.Get("page").Int(), r.Get("limit").Int(), r.Get("searchParams")))
}

// SearchSubDomainDetails 模糊分页查询子域名扫描详情
func (a *collectorApi) SearchSubDomainDetails(r *ghttp.Request) {
	taskName := r.Get("taskname").String()
	if taskName == "" {
		response.JsonExit(r, 201, "任务名错误")
	}
	r.Response.WriteJson(service.Collector.SearchSubDomainDetails(r.Context(), r.Get("page").Int(), r.Get("limit").Int(), taskName, r.Get("searchParams")))
}

// DelSubDomainTask 子域名扫描删除指定任务数据
func (a *collectorApi) DelSubDomainTask(r *ghttp.Request) {
	var (
		data *model.UtilSubdomainTaskDelReq
	)
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.Collector.DelSubDomainTask(r.Context(), data); err != nil {
		response.JsonExit(r, 201, err.Error())
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "Util-子域名扫描删除任务", fmt.Sprintf("任务名[%s]", data.CusName))
		response.JsonExit(r, 200, "ok")
	}
}

// EmptySubDomainTask 清空子域名扫描任务
func (a *collectorApi) EmptySubDomainTask(r *ghttp.Request) {
	if err := service.Collector.EmptySubDomainTask(r.Context()); err != nil {
		response.JsonExit(r, 201, "清空子域名扫描数据失败,数据库错误")
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "Util-子域名扫描清空数据", "清空数据成功")
		response.JsonExit(r, 200, "ok")
	}
}

// AddPortScanTask 添加端口扫描任务
func (a *collectorApi) AddPortScanTask(r *ghttp.Request) {
	var (
		data *model.UtilPortScanApiAddReq
	)
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if result, err := service.Collector.AddPortScanTask(r.Context(), data); err != nil {
		response.JsonExit(r, 201, err.Error())
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "信息搜集-添加端口扫描任务", result)
		response.JsonExit(r, 200, result)
	}
}

// SearchPortScanTask 模糊分页查询端口扫描任务
func (a *collectorApi) SearchPortScanTask(r *ghttp.Request) {
	r.Response.WriteJson(service.Collector.SearchPortScanTask(r.Context(), r.Get("page").Int(), r.Get("limit").Int(), r.Get("searchParams")))
}

// DelPortScanTask 删除指定任务端口扫描数据
func (a *collectorApi) DelPortScanTask(r *ghttp.Request) {
	var (
		data *model.UtilSubdomainTaskDelReq
	)
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.Collector.DelPortScanTask(r.Context(), data); err != nil {
		response.JsonExit(r, 201, err.Error())
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "端口扫描删除任务", fmt.Sprintf("任务名[%s]", data.CusName))
		response.JsonExit(r, 200, "ok")
	}
}

// EmptyPortScanTask 清空所有端口扫描数据
func (a *collectorApi) EmptyPortScanTask(r *ghttp.Request) {
	if err := service.Collector.EmptyPortScanTask(r.Context()); err != nil {
		response.JsonExit(r, 201, "清空端口扫描数据失败,数据库错误")
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "端口扫描清空数据", "清空数据成功")
		response.JsonExit(r, 200, "ok")
	}
}

// SearchPortScanDetails 端口扫描详情分页查询
func (a *collectorApi) SearchPortScanDetails(r *ghttp.Request) {
	taskName := r.Get("taskname").String()
	if taskName == "" {
		response.JsonExit(r, 201, "任务名错误")
	}
	r.Response.WriteJson(service.Collector.SearchPortScanDetails(r.Context(), r.Get("page").Int(), r.Get("limit").Int(), taskName, r.Get("searchParams")))
}
