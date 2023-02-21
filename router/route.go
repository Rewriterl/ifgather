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
			group.GET("/engine/nsq/portscan", controller.Scan.NsqPortScanStat)
			group.GET("/engine/nsq/subdomain", controller.Scan.NsqSubDomainStat)
			group.GET("/engine/nsq/webinfo", controller.Scan.NsqWebInfoStat)
			group.GET("/client/info", controller.Scan.GetApiKeyEngine)
			group.DELETE("/engine/emptydomain", controller.Scan.EmptyDomain)
			group.DELETE("/engine/emptyport", controller.Scan.EmptyPort)
			group.DELETE("/engine/emptywebinfo", controller.Scan.EmptyWebInfo)
			group.POST("/manager", controller.Scan.ManagerAdd)
			group.DELETE("/manager", controller.Scan.ManagerDelete)
			group.GET("/manager", controller.Scan.SearchManager)
			group.POST("/domain", controller.Scan.AddDomain)
			group.GET("/domain", controller.Scan.SearchDomain)
			group.GET("/group/cusname", controller.Scan.GetApiCusName)
			group.GET("/subdomain", controller.Scan.SearchSubDomain)
			group.GET("/port", controller.Scan.SearchPortScan)
			group.GET("/webinfo", controller.Scan.SearchWebInfo)
			group.POST("/webinfo/tree", controller.Scan.WebInfoTree)
			group.DELETE("/webinfo", controller.Scan.DelWebInfo)
		})
		group.Group("/collector", func(group *ghttp.RouterGroup) {
			group.Middleware(service.Middleware.Auth)
			//TODO: 对数据库操作,命名暂时有些问题，不太好和scan区分开
			group.POST("/subdomain", controller.Collector.AddSubDomainTask)
			group.GET("/subdomain", controller.Collector.SearchSubDomainTask)
			group.GET("/subdomain/details", controller.Collector.SearchSubDomainDetails)
			group.DELETE("/subdomain", controller.Collector.DelSubDomainTask)
			group.DELETE("/subdomain/all", controller.Collector.EmptySubDomainTask)
			group.POST("/portscan", controller.Collector.AddPortScanTask)
			group.GET("/portscan", controller.Collector.SearchPortScanTask)
			group.DELETE("/portscan", controller.Collector.DelPortScanTask)
			group.DELETE("/portscan/all", controller.Collector.EmptyPortScanTask)
			group.GET("/portscan/details", controller.Collector.SearchPortScanDetails)
			group.GET("/portscan/echarts", controller.Collector.GetPortScanEchartsInfo)
		})
	})
}
