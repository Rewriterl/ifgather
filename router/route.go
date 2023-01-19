package router

import (
	"github.com/Rewriterl/ifgather/internal/controller"
	"github.com/Rewriterl/ifgather/internal/service"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
)

func init() {
	server := g.Server()
	server.BindStatusHandler(404, func(r *ghttp.Request) {
		r.Response.RedirectTo("/")
	})
	server.BindStatusHandler(403, func(r *ghttp.Request) {
		r.Response.RedirectTo("/")
	})
	server.Group("/", func(group *ghttp.RouterGroup) {
		group.Middleware(service.Middleware.Ctx)
		group.POST("/login", controller.Users.Login)
		group.Group("/user", func(group *ghttp.RouterGroup) {
			group.Middleware(service.Middleware.Auth)
			group.POST("/", controller.Users.AddUser)
			group.DELETE("/", controller.Users.DelUser)
			group.GET("/", controller.Users.GetUserInfo)
			group.PATCH("/", controller.Users.PatchUserInfo)
			group.POST("/logout", controller.Users.LoginOut)
			group.POST("/password", controller.Users.ChangePassword)
			group.GET("/llogs", controller.Users.SearchUserLoginLogs)
			group.GET("/optlogs", controller.Users.SearchUserOperation)
		})
		group.Group("/users", func(group *ghttp.RouterGroup) {
			group.Middleware(service.Middleware.Auth)
			group.GET("/", controller.Users.SearchUser)
		})
		group.Group("/scan", func(group *ghttp.RouterGroup) {
			group.Middleware(service.Middleware.Auth)
			group.POST("/engine/apikey", controller.Scan.SetAPIKeyEngineNsq)
			group.POST("/engine/portscan", controller.Scan.SetApiKeyEnginePortScan)
			group.POST("/engine/domain", controller.Scan.SetApiKeyEngineDomain)
		})
	})
}
