package main

import (
	"github.com/Rewriterl/ifgather/internal/cmd"
	_ "github.com/Rewriterl/ifgather/router"
	_ "github.com/gogf/gf/contrib/drivers/pgsql/v2"
	"github.com/gogf/gf/v2/os/gctx"
)

func main() {
	cmd.Main.Run(gctx.New())
}
