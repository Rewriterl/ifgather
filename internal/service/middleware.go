package service

import (
	"context"
	"github.com/Rewriterl/ifgather/internal/model"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
)

const (
	sessionKeyUser = "ifgather"
)

type serviceMiddleware struct{}

type serviceSession struct{}

type serviceContext struct{}

var Middleware = new(serviceMiddleware)

var Session = new(serviceSession)

var Context = new(serviceContext)

func (s *serviceMiddleware) Ctx(r *ghttp.Request) {
	customCtx := &model.Context{
		Session: r.Session,
	}
	Context.Init(r, customCtx)
	if user := Session.GetUser(r.Context()); user != nil {
		customCtx.User = &model.ContextUser{
			Id:       user.Id,
			UserName: user.Username,
			Email:    user.Email,
		}
	}
	r.Middleware.Next()
}

func (s *serviceContext) Init(r *ghttp.Request, customCtx *model.Context) {
	r.SetCtxVar(model.ContextKey, customCtx)
}

func (s *serviceMiddleware) Auth(r *ghttp.Request) {
	if User.IsSignedIn(r.Context()) {
		r.Middleware.Next()
	} else {
		r.Response.WriteJsonExit(g.Map{"code": 403, "msg": "非法访问", "data": ""})
	}
}

func (s *serviceSession) GetUser(ctx context.Context) *model.Users {
	customCtx := Context.Get(ctx)
	if customCtx != nil {
		if v, _ := customCtx.Session.Get(sessionKeyUser); !v.IsNil() {
			var user *model.Users
			_ = v.Struct(&user)
			return user
		}
	}
	return nil
}

func (s *serviceContext) Get(ctx context.Context) *model.Context {
	value := ctx.Value(model.ContextKey)
	if value == nil {
		return nil
	}
	if localCtx, ok := value.(*model.Context); ok {
		return localCtx
	}
	return nil
}

func (s *serviceSession) SetUser(ctx context.Context, user *model.Users) error {
	return Context.Get(ctx).Session.Set(sessionKeyUser, user)
}

func (s *serviceSession) RemoveUser(ctx context.Context) error {
	customCtx := Context.Get(ctx)
	if customCtx != nil {
		return customCtx.Session.Remove(sessionKeyUser)
	}
	return nil
}
