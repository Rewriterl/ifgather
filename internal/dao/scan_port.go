// =================================================================================
// This is auto-generated by GoFrame CLI tool only once. Fill this file as you wish.
// =================================================================================

package dao

import (
	"github.com/Rewriterl/ifgather/internal/dao/internal"
)

// internalScanPortDao is internal type for wrapping internal DAO implements.
type internalScanPortDao = *internal.ScanPortDao

// scanPortDao is the data access object for table scan_port.
// You can define custom methods on it to extend its functionality as you wish.
type scanPortDao struct {
	internalScanPortDao
}

var (
	// ScanPort is globally public accessible object for table scan_port operations.
	ScanPort = scanPortDao{
		internal.NewScanPortDao(),
	}
)

// Fill with you ideas below.
