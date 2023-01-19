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

// SetNsqEngine 扫描引擎 添加nsq地址
func (s *serviceScanEngine) SetNsqEngine(ctx context.Context, r *model.APIKeyEngineNsqReq) error {
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

// SetPortScanEngine 扫描引擎 添加端口扫描
func (s *serviceScanEngine) SetPortScanEngine(ctx context.Context, r *model.ApiKeyEnginePortScanReq) error {
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

// SetDomainEngine 扫描引擎 添加子域名
func (s *serviceScanEngine) SetDomainEngine(ctx context.Context, r *model.ApiKeyEngineDomainReq) error {
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

// SetApiKeyEngine 扫描引擎 添加API秘钥
func (s *serviceScanEngine) SetApiKeyEngine(ctx context.Context, r *model.ApiKeyEngineKeyReq) error {
	count, err := dao.ApiKey.Ctx(ctx).Where("key=?", "engine_apikey").Count()
	returnErr := errors.New("保存失败,数据库错误")
	if err != nil {
		logger.WebLog.Warningf(ctx, "扫描引擎-API秘钥查询失败:%s", err.Error())
		return returnErr
	}
	jsonstr, err := gjson.New(r).ToJsonString()
	if err != nil {
		logger.WebLog.Warningf(ctx, "扫描引擎-API秘钥序列化失败:%s", err.Error())
		return returnErr
	}
	if count != 0 {
		if _, err := dao.ApiKey.Ctx(ctx).Update(g.Map{"value": jsonstr}, "key", "engine_apikey"); err != nil {
			logger.WebLog.Warningf(ctx, "扫描引擎-API秘钥更新失败:%s", err.Error())
			return returnErr
		}
	} else {
		if _, err := dao.ApiKey.Ctx(ctx).Insert(g.Map{"key": "engine_apikey", "value": jsonstr}); err != nil {
			logger.WebLog.Warningf(ctx, "扫描引擎-API秘钥保存失败:%s", err.Error())
			return returnErr
		}
	}
	return nil
}

// SetWebInfoEngine 扫描引擎 添加Web探测
func (s *serviceScanEngine) SetWebInfoEngine(ctx context.Context, r *model.ApiKeyEngineWebInfoReq) error {
	count, err := dao.ApiKey.Ctx(ctx).Where("key=?", "engine_webinfo").Count()
	returnErr := errors.New("保存失败,数据库错误")
	if err != nil {
		logger.WebLog.Warningf(ctx, "扫描引擎-web探测查询失败:%s", err.Error())
		return returnErr
	}
	jsonstr, err := gjson.New(r).ToJsonString()
	if err != nil {
		logger.WebLog.Warningf(ctx, "扫描引擎-web探测序列化失败:%s", err.Error())
		return returnErr
	}
	if count != 0 {
		if _, err := dao.ApiKey.Ctx(ctx).Update(g.Map{"value": jsonstr}, "key", "engine_webinfo"); err != nil {
			logger.WebLog.Warningf(ctx, "扫描引擎-web探测更新失败:%s", err.Error())
			return returnErr
		}
	} else {
		if _, err := dao.ApiKey.Ctx(ctx).Insert(g.Map{"key": "engine_webinfo", "value": jsonstr}); err != nil {
			logger.WebLog.Warningf(ctx, "扫描引擎-web探测保存失败:%s", err.Error())
			return returnErr
		}
	}
	return nil
}
