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
			group.POST("/engine/nsq", controller.Scan.SetNsqEngine)
			group.POST("/engine/portscan", controller.Scan.SetPortScanEngine)
			group.POST("/engine/domain", controller.Scan.SetDomainEngine)
			group.POST("/engine/apikey", controller.Scan.SetApiKeyEngine)
			group.POST("/engine/webinfo", controller.Scan.SetWebInfoEngine)
			group.GET("/client/info", controller.Scan.GetApiKeyEngine)
			group.DELETE("/engine/emptydomain", controller.Scan.EmptyDomain)
			group.DELETE("/engine/emptyport", controller.Scan.EmptyPort)
			group.DELETE("/engine/emptywebinfo", controller.Scan.EmptyWebInfo)
			group.POST("/manager", controller.Scan.ManagerAdd)
			group.DELETE("/manager", controller.Scan.ManagerDelete)
			group.GET("/manager", controller.Scan.SearchManager)
		})
	})
}
