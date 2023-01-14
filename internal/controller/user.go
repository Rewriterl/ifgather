package controller

import (
	"fmt"
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

func (a *apiUser) GetUserInfo(r *ghttp.Request) {
	response.JsonExit(r, 200, "ok", service.User.UserInfo(r.Context()))
}
func (a *apiUser) LoginOut(r *ghttp.Request) {
	service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "注销用户", "注销成功")
	if err := service.User.Logout(r.Context()); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	response.JsonExit(r, 200, "ok")
}

func (a *apiUser) SearchUser(r *ghttp.Request) {
	r.Response.WriteJson(service.User.SearchUser(r.Context(), r.Get("page").Int(), r.Get("limit").Int(), r.Get("searchParams")))
}

func (a *apiUser) AddUser(r *ghttp.Request) {
	if !service.User.IsAdmin(r.Context()) {
		response.JsonExit(r, 201, "权限不足")
	}
	var data *model.UsersApiRegisterReq
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.User.AddUser(r.Context(), data); err != nil {
		response.JsonExit(r, 202, err.Error())
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "添加用户", fmt.Sprintf("添加[%s]用户", data.Username))
		response.JsonExit(r, 200, "ok")
	}
}

func (a *apiUser) ChangePassword(r *ghttp.Request) {
	var data *model.UserApiChangePasswordReq
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.User.ChangePassword(r.Context(), data); err != nil {
		response.JsonExit(r, 202, err.Error())
	} else {
		_ = service.User.Logout(r.Context())
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "密码修改", "修改成功")
		response.JsonExit(r, 200, "密码修改成功，请重新登录")
	}
}

func (a *apiUser) DelUser(r *ghttp.Request) {
	if !service.User.IsAdmin(r.Context()) {
		response.JsonExit(r, 201, "权限不足")
	}
	var data *model.UserApiDelReq
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.User.UserDel(r.Context(), data); err != nil {
		response.JsonExit(r, 202, err.Error())
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "删除用户", fmt.Sprintf("删除ID为 [%s] 的用户", data.Id))
		response.JsonExit(r, 200, "ok")
	}
}

func (a *apiUser) PatchUserInfo(r *ghttp.Request) {
	var data *model.UserApiSetInfoReq
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.User.SetUserInfo(r.Context(), data); err != nil {
		response.JsonExit(r, 202, err.Error())
	} else {
		service.User.AddUserOptLog(r.Context(), r.GetRemoteIp(), "资料修改", fmt.Sprintf("成功修改 [%s]", data.NickName))
		response.JsonExit(r, 200, "ok")
	}
}
