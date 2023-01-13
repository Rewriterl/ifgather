package main

import (
	"github.com/Rewriterl/ifgather/internal/cmd"
	"github.com/gogf/gf/v2/os/gctx"

	_ "github.com/Rewriterl/ifgather/utility/pqsql"
)

func main() {
	cmd.Main.Run(gctx.New())
}
