package main

import (
	"github.com/Rewriterl/ifgather/internal/cmd"
	_ "github.com/Rewriterl/ifgather/router"
	_ "github.com/Rewriterl/ifgather/utility/pqsql"
	"github.com/gogf/gf/v2/os/gctx"
)

func main() {
	cmd.Main.Run(gctx.New())
}
