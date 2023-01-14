package controller

import (
	"github.com/Rewriterl/ifgather/internal/model"
	"github.com/Rewriterl/ifgather/internal/service"
	"github.com/Rewriterl/ifgather/utility/response"
	"github.com/gogf/gf/v2/net/ghttp"
)

type apiUser struct{}

var Users = new(apiUser)

func (a *apiUser) Login(r *ghttp.Request) {
	var data *model.UsersApiLoginReq
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.User.Login(r.Context(), data, r.GetRemoteIp(), r.GetHeader("User-Agent")); err != nil {
		response.JsonExit(r, 202, err.Error())
	} else {
		response.JsonExit(r, 200, "ok")
	}
}

func (a *apiUser) UserInfo(r *ghttp.Request) {
	response.JsonExit(r, 200, "ok", service.User.UserInfo(r.Context()))
}
func (a *apiUser) LoginOut(r *ghttp.Request) {
	service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "注销用户", "注销成功")
	if err := service.User.Logout(r.Context()); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	response.JsonExit(r, 200, "ok")
}
