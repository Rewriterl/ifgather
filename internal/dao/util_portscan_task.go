// =================================================================================
// This is auto-generated by GoFrame CLI tool only once. Fill this file as you wish.
// =================================================================================

package dao

import (
	"github.com/Rewriterl/ifgather/internal/dao/internal"
)

// internalUtilPortscanTaskDao is internal type for wrapping internal DAO implements.
type internalUtilPortscanTaskDao = *internal.UtilPortscanTaskDao

// utilPortscanTaskDao is the data access object for table util_portscan_task.
// You can define custom methods on it to extend its functionality as you wish.
type utilPortscanTaskDao struct {
	internalUtilPortscanTaskDao
}

var (
	// UtilPortscanTask is globally public accessible object for table util_portscan_task operations.
	UtilPortscanTask = utilPortscanTaskDao{
		internal.NewUtilPortscanTaskDao(),
	}
)

// Fill with you ideas below.
