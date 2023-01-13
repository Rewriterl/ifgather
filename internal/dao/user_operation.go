// =================================================================================
// This is auto-generated by GoFrame CLI tool only once. Fill this file as you wish.
// =================================================================================

package dao

import (
	"github.com/Rewriterl/ifgather/internal/dao/internal"
)

// internalUserOperationDao is internal type for wrapping internal DAO implements.
type internalUserOperationDao = *internal.UserOperationDao

// userOperationDao is the data access object for table user_operation.
// You can define custom methods on it to extend its functionality as you wish.
type userOperationDao struct {
	internalUserOperationDao
}

var (
	// UserOperation is globally public accessible object for table user_operation operations.
	UserOperation = userOperationDao{
		internal.NewUserOperationDao(),
	}
)

// Fill with you ideas below.
