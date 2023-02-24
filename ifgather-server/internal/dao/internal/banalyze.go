// ==========================================================================
// Code generated by GoFrame CLI tool. DO NOT EDIT.
// ==========================================================================

package internal

import (
	"context"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
)

// BanalyzeDao is the data access object for table banalyze.
type BanalyzeDao struct {
	table   string          // table is the underlying table name of the DAO.
	group   string          // group is the database configuration group name of current DAO.
	columns BanalyzeColumns // columns contains all the column names of Table for convenient usage.
}

// BanalyzeColumns defines and stores column names for table banalyze.
type BanalyzeColumns struct {
	Id          string //
	Key         string //
	Description string //
	Value       string //
	CreateAt    string //
}

// banalyzeColumns holds the columns for table banalyze.
var banalyzeColumns = BanalyzeColumns{
	Id:          "id",
	Key:         "key",
	Description: "description",
	Value:       "value",
	CreateAt:    "create_at",
}

// NewBanalyzeDao creates and returns a new DAO object for table data access.
func NewBanalyzeDao() *BanalyzeDao {
	return &BanalyzeDao{
		group:   "default",
		table:   "banalyze",
		columns: banalyzeColumns,
	}
}

// DB retrieves and returns the underlying raw database management object of current DAO.
func (dao *BanalyzeDao) DB() gdb.DB {
	return g.DB(dao.group)
}

// Table returns the table name of current dao.
func (dao *BanalyzeDao) Table() string {
	return dao.table
}

// Columns returns all column names of current dao.
func (dao *BanalyzeDao) Columns() BanalyzeColumns {
	return dao.columns
}

// Group returns the configuration group name of database of current dao.
func (dao *BanalyzeDao) Group() string {
	return dao.group
}

// Ctx creates and returns the Model for current DAO, It automatically sets the context for current operation.
func (dao *BanalyzeDao) Ctx(ctx context.Context) *gdb.Model {
	return dao.DB().Model(dao.table).Safe().Ctx(ctx)
}

// Transaction wraps the transaction logic using function f.
// It rollbacks the transaction and returns the error from function f if it returns non-nil error.
// It commits the transaction and returns nil if function f returns nil.
//
// Note that, you should not Commit or Rollback the transaction in function f
// as it is automatically handled by this function.
func (dao *BanalyzeDao) Transaction(ctx context.Context, f func(ctx context.Context, tx gdb.TX) error) (err error) {
	return dao.Ctx(ctx).Transaction(ctx, f)
}