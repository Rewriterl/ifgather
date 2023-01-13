package controller

import (
	"context"
	v1 "github.com/Rewriterl/ifgather/api/v1"
	"github.com/Rewriterl/ifgather/internal/dao"
	"github.com/gogf/gf/v2/frame/g"
)

var (
	Hello = cHello{}
)

type cHello struct{}

func (c *cHello) Hello(ctx context.Context, req *v1.HelloReq) (res *v1.HelloRes, err error) {
	one, err := dao.Users.Ctx(ctx).Where("id = ?", 3).One()
	if err != nil {
		return nil, err
	}
	g.RequestFromCtx(ctx).Response.Writeln(one)
	return
}
