package tools

import (
	"database/sql"
	"github.com/gogf/gf/v2/database/gdb"
)

type ScanDomain struct {
	Domain string `v:"domain#主域名不正确"`
}

func TransToStruct(one gdb.Record, out interface{}) error {
	if err := one.Struct(out); err != nil && err != sql.ErrNoRows {
		return err
	}
	return nil
}

func TransToStructs(all gdb.Result, out interface{}) error {
	if err := all.Structs(out); err != nil && err != sql.ErrNoRows {
		return err
	}
	return nil
}
