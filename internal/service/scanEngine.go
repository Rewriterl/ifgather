package service

import (
	"context"
	"errors"
	"github.com/Rewriterl/ifgather/internal/dao"
	"github.com/Rewriterl/ifgather/internal/model"
	"github.com/Rewriterl/ifgather/utility/logger"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
)

var ScanEngine = new(serviceScanEngine)

type serviceScanEngine struct{}

// SetAPIKeyEngineNsq 扫描引擎 添加nsq地址
func (s *serviceScanEngine) SetAPIKeyEngineNsq(ctx context.Context, r *model.APIKeyEngineNsqReq) error {
	count, err := dao.ApiKey.Ctx(ctx).Where("key=?", "engine_nsq").Count()
	returnErr := errors.New("保存失败")
	if err != nil {
		logger.WebLog.Warningf(ctx, "查询扫描引擎nsq数据库错误:%s", err.Error())
		return returnErr
	}
	jsonstr, err := gjson.New(r).ToJsonString()
	if err != nil {
		logger.WebLog.Warningf(ctx, "扫描引擎-nsq json序列化失败:%s", err.Error())
		return returnErr
	}
	if count != 0 {
		if _, err := dao.ApiKey.Ctx(ctx).Update(g.Map{"value": jsonstr}, "key", "engine_nsq"); err != nil {
			logger.WebLog.Warningf(ctx, "扫描引擎-nsq更新失败:%s", err.Error())
			return returnErr
		}
	} else {
		if _, err := dao.ApiKey.Ctx(ctx).Insert(g.Map{"key": "engine_nsq", "value": jsonstr}); err != nil {
			logger.WebLog.Warningf(ctx, "扫描引擎-nsq保存失败:%s", err.Error())
			return returnErr
		}
	}
	return nil
}
