// =================================================================================
// This is auto-generated by GoFrame CLI tool only once. Fill this file as you wish.
// =================================================================================

package dao

import (
	"github.com/Rewriterl/ifgather-server/internal/dao/internal"
)

// internalUtilPortscanResultDao is do type for wrapping do DAO implements.
type internalUtilPortscanResultDao = *internal.UtilPortscanResultDao

// utilPortscanResultDao is the data access object for table util_portscan_result.
// You can define custom methods on it to extend its functionality as you wish.
type utilPortscanResultDao struct {
	internalUtilPortscanResultDao
}

var (
	// UtilPortscanResult is globally public accessible object for table util_portscan_result operations.
	UtilPortscanResult = utilPortscanResultDao{
		internal.NewUtilPortscanResultDao(),
	}
)

// Fill with you ideas below.
