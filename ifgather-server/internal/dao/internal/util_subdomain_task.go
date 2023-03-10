// ==========================================================================
// Code generated by GoFrame CLI tool. DO NOT EDIT.
// ==========================================================================

package internal

import (
	"context"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
)

// UtilSubdomainTaskDao is the data access object for table util_subdomain_task.
type UtilSubdomainTaskDao struct {
	table   string                   // table is the underlying table name of the DAO.
	group   string                   // group is the database configuration group name of current DAO.
	columns UtilSubdomainTaskColumns // columns contains all the column names of Table for convenient usage.
}

// UtilSubdomainTaskColumns defines and stores column names for table util_subdomain_task.
type UtilSubdomainTaskColumns struct {
	Id        string //
	CusName   string //
	DomainNum string //
	ScanNum   string //
	CreateAt  string //
}

// utilSubdomainTaskColumns holds the columns for table util_subdomain_task.
var utilSubdomainTaskColumns = UtilSubdomainTaskColumns{
	Id:        "id",
	CusName:   "cus_name",
	DomainNum: "domain_num",
	ScanNum:   "scan_num",
	CreateAt:  "create_at",
}

// NewUtilSubdomainTaskDao creates and returns a new DAO object for table data access.
func NewUtilSubdomainTaskDao() *UtilSubdomainTaskDao {
	return &UtilSubdomainTaskDao{
		group:   "default",
		table:   "util_subdomain_task",
		columns: utilSubdomainTaskColumns,
	}
}

// DB retrieves and returns the underlying raw database management object of current DAO.
func (dao *UtilSubdomainTaskDao) DB() gdb.DB {
	return g.DB(dao.group)
}

// Table returns the table name of current dao.
func (dao *UtilSubdomainTaskDao) Table() string {
	return dao.table
}

// Columns returns all column names of current dao.
func (dao *UtilSubdomainTaskDao) Columns() UtilSubdomainTaskColumns {
	return dao.columns
}

// Group returns the configuration group name of database of current dao.
func (dao *UtilSubdomainTaskDao) Group() string {
	return dao.group
}

// Ctx creates and returns the Model for current DAO, It automatically sets the context for current operation.
func (dao *UtilSubdomainTaskDao) Ctx(ctx context.Context) *gdb.Model {
	return dao.DB().Model(dao.table).Safe().Ctx(ctx)
}

// Transaction wraps the transaction logic using function f.
// It rollbacks the transaction and returns the error from function f if it returns non-nil error.
// It commits the transaction and returns nil if function f returns nil.
//
// Note that, you should not Commit or Rollback the transaction in function f
// as it is automatically handled by this function.
func (dao *UtilSubdomainTaskDao) Transaction(ctx context.Context, f func(ctx context.Context, tx gdb.TX) error) (err error) {
	return dao.Ctx(ctx).Transaction(ctx, f)
}
