package tools

import (
	"database/sql"
	"github.com/gogf/gf/v2/database/gdb"
)

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
