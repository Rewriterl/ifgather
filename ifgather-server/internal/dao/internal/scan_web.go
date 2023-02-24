// ==========================================================================
// Code generated by GoFrame CLI tool. DO NOT EDIT.
// ==========================================================================

package internal

import (
	"context"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
)

// ScanWebDao is the data access object for table scan_web.
type ScanWebDao struct {
	table   string         // table is the underlying table name of the DAO.
	group   string         // group is the database configuration group name of current DAO.
	columns ScanWebColumns // columns contains all the column names of Table for convenient usage.
}

// ScanWebColumns defines and stores column names for table scan_web.
type ScanWebColumns struct {
	Id             string //
	CusName        string //
	Url            string //
	Code           string //
	Title          string //
	ContentLength  string //
	Fingerprint    string //
	Image          string //
	ScreenshotFlag string //
	Js             string //
	Urls           string //
	Forms          string //
	Secret         string //
	Flag           string //
	NsqFlag        string //
	ScanFlag       string //
	ScanNsqFlag    string //
	CreateAt       string //
}

// scanWebColumns holds the columns for table scan_web.
var scanWebColumns = ScanWebColumns{
	Id:             "id",
	CusName:        "cus_name",
	Url:            "url",
	Code:           "code",
	Title:          "title",
	ContentLength:  "content_length",
	Fingerprint:    "fingerprint",
	Image:          "image",
	ScreenshotFlag: "screenshot_flag",
	Js:             "js",
	Urls:           "urls",
	Forms:          "forms",
	Secret:         "secret",
	Flag:           "flag",
	NsqFlag:        "nsq_flag",
	ScanFlag:       "scan_flag",
	ScanNsqFlag:    "scan_nsq_flag",
	CreateAt:       "create_at",
}

// NewScanWebDao creates and returns a new DAO object for table data access.
func NewScanWebDao() *ScanWebDao {
	return &ScanWebDao{
		group:   "default",
		table:   "scan_web",
		columns: scanWebColumns,
	}
}

// DB retrieves and returns the underlying raw database management object of current DAO.
func (dao *ScanWebDao) DB() gdb.DB {
	return g.DB(dao.group)
}

// Table returns the table name of current dao.
func (dao *ScanWebDao) Table() string {
	return dao.table
}

// Columns returns all column names of current dao.
func (dao *ScanWebDao) Columns() ScanWebColumns {
	return dao.columns
}

// Group returns the configuration group name of database of current dao.
func (dao *ScanWebDao) Group() string {
	return dao.group
}

// Ctx creates and returns the Model for current DAO, It automatically sets the context for current operation.
func (dao *ScanWebDao) Ctx(ctx context.Context) *gdb.Model {
	return dao.DB().Model(dao.table).Safe().Ctx(ctx)
}

// Transaction wraps the transaction logic using function f.
// It rollbacks the transaction and returns the error from function f if it returns non-nil error.
// It commits the transaction and returns nil if function f returns nil.
//
// Note that, you should not Commit or Rollback the transaction in function f
// as it is automatically handled by this function.
func (dao *ScanWebDao) Transaction(ctx context.Context, f func(ctx context.Context, tx gdb.TX) error) (err error) {
	return dao.Ctx(ctx).Transaction(ctx, f)
}