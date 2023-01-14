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
			group.GET("/", controller.Users.UserInfo)
			group.POST("/", controller.Users.AddUser)
			group.POST("/logout", controller.Users.LoginOut)
			group.POST("/password", controller.Users.ChangePassword)
		})
		group.Group("/users", func(group *ghttp.RouterGroup) {
			group.Middleware(service.Middleware.Auth)
			group.GET("/", controller.Users.SearchUser)
		})
	})
}
