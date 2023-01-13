// =================================================================================
// This is auto-generated by GoFrame CLI tool only once. Fill this file as you wish.
// =================================================================================

package dao

import (
	"github.com/Rewriterl/ifgather/internal/dao/internal"
)

// internalApiKeyDao is do type for wrapping do DAO implements.
type internalApiKeyDao = *internal.ApiKeyDao

// apiKeyDao is the data access object for table api_key.
// You can define custom methods on it to extend its functionality as you wish.
type apiKeyDao struct {
	internalApiKeyDao
}

var (
	// ApiKey is globally public accessible object for table api_key operations.
	ApiKey = apiKeyDao{
		internal.NewApiKeyDao(),
	}
)

// Fill with you ideas below.
