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

// SetApiKeyEnginePortScan 扫描引擎 添加端口扫描
func (s *serviceScanEngine) SetApiKeyEnginePortScan(ctx context.Context, r *model.ApiKeyEnginePortScanReq) error {
	count, err := dao.ApiKey.Ctx(ctx).Where("key=?", "engine_portscan").Count()
	returnErr := errors.New("保存失败")
	if err != nil {
		logger.WebLog.Warningf(ctx, "扫描引擎-端口扫描查询数据库失败:%s", err.Error())
		return returnErr
	}
	jsonstr, err := gjson.New(r).ToJsonString()
	if err != nil {
		logger.WebLog.Warningf(ctx, "扫描引擎-端口扫描序列化失败:%s", err.Error())
		return returnErr
	}
	if count != 0 {
		if _, err := dao.ApiKey.Ctx(ctx).Update(g.Map{"value": jsonstr}, "key", "engine_portscan"); err != nil {
			logger.WebLog.Warningf(ctx, "扫描引擎-端口扫描更新失败:%s", err.Error())
			return returnErr
		}
	} else {
		if _, err := dao.ApiKey.Ctx(ctx).Insert(g.Map{"key": "engine_portscan", "value": jsonstr}); err != nil {
			logger.WebLog.Warningf(ctx, "扫描引擎-端口扫描保存失败:%s", err.Error())
			return returnErr
		}
	}
	return nil
}

// SetApiKeyEngineDomain 扫描引擎 添加子域名
func (s *serviceScanEngine) SetApiKeyEngineDomain(ctx context.Context, r *model.ApiKeyEngineDomainReq) error {
	count, err := dao.ApiKey.Ctx(ctx).Where("key=?", "engine_domain").Count()
	reurnErr := errors.New("保存失败")
	if err != nil {
		logger.WebLog.Warningf(ctx, "扫描引擎-子域名查询失败:%s", err.Error())
		return reurnErr
	}
	jsonstr, err := gjson.New(r).ToJsonString()
	if err != nil {
		logger.WebLog.Warningf(ctx, "扫描引擎-子域名序列化失败:%s", err.Error())
		return reurnErr
	}
	if count != 0 {
		if _, err := dao.ApiKey.Ctx(ctx).Update(g.Map{"value": jsonstr}, "key", "engine_domain"); err != nil {
			logger.WebLog.Warningf(ctx, "扫描引擎-子域名更新失败:%s", err.Error())
			return reurnErr
		}
	} else {
		if _, err := dao.ApiKey.Ctx(ctx).Insert(g.Map{"key": "engine_domain", "value": jsonstr}); err != nil {
			logger.WebLog.Warningf(ctx, "扫描引擎-子域名保存失败:%s", err.Error())
			return reurnErr
		}
	}
	return nil
}
