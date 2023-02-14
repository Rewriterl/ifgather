package service

import (
	"context"
	"database/sql"
	"errors"
	"github.com/Rewriterl/ifgather/internal/dao"
	"github.com/Rewriterl/ifgather/internal/model"
	"github.com/Rewriterl/ifgather/utility/banalyze"
	"github.com/Rewriterl/ifgather/utility/logger"
	Gnsq "github.com/Rewriterl/ifgather/utility/nsq"
	"github.com/Rewriterl/ifgather/utility/nsq/producer"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/util/gconv"
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

// GetApiKeyEngine 扫描引擎 输出配置
func (s *serviceScanEngine) GetApiKeyEngine(ctx context.Context) *model.ResApiKeyEngine {
	result := model.ResApiKeyEngine{}

	one, err := dao.ApiKey.Ctx(ctx).Where("key=?", "engine_nsq").One()
	jsonNsq, err := TransToApiKey(one)
	if err == nil && jsonNsq != nil {
		j, err := gjson.DecodeToJson(jsonNsq.Value)
		structs := model.APIKeyEngineNsqReq{}
		if err == nil {
			err := gconv.Struct(j, &structs)
			if err == nil {
				result.Nsq = structs
			}
		}
	}
	one, err = dao.ApiKey.Ctx(ctx).Where("key=?", "engine_portscan").One()
	jsonPortScan, err := TransToApiKey(one)
	if err == nil && jsonPortScan != nil {
		j, err := gjson.DecodeToJson(jsonPortScan.Value)
		structs := model.ApiKeyEnginePortScanReq{}
		if err == nil {
			err = gconv.Struct(j, &structs)
			if err == nil {
				result.PortScan = structs
			}
		}
	}
	one, err = dao.ApiKey.Ctx(ctx).Where("key=?", "engine_domain").One()
	jsonDomain, err := TransToApiKey(one)
	if err == nil && jsonDomain != nil {
		j, err := gjson.DecodeToJson(jsonDomain.Value)
		structs := model.ApiKeyEngineDomainReq{}
		if err == nil {
			err = gconv.Struct(j, &structs)
			if err == nil {
				result.Domain = structs
			}
		}
	}
	one, err = dao.ApiKey.Ctx(ctx).Where("key=?", "engine_apikey").One()
	jsonApiKey, err := TransToApiKey(one)
	if err == nil && jsonApiKey != nil {
		j, err := gjson.DecodeToJson(jsonApiKey.Value)
		structs := model.ApiKeyEngineKeyReq{}
		if err == nil {
			err = gconv.Struct(j, &structs)
			if err == nil {
				structs.Binaryedge = "******"
				structs.CensysSecret = "******"
				structs.CensysToken = "******"
				structs.Certspotter = "******"
				structs.GitHub = "******"
				structs.Shodan = "******"
				structs.Spyse = "******"
				structs.URLScan = "******"
				structs.ThreatBook = "******"
				structs.Virustotal = "******"
				structs.Securitytrails = "******"
				result.ApiKey = structs
			}
		}
	}

	one, err = dao.ApiKey.Ctx(ctx).Where("key=?", "engine_webinfo").One()
	jsonWebInfo, err := TransToApiKey(one)
	if err == nil && jsonWebInfo != nil {
		j, err := gjson.DecodeToJson(jsonWebInfo.Value)
		structs := model.ApiKeyEngineWebInfoReq{}
		if err == nil {
			err = gconv.Struct(j, &structs)
			if err == nil {
				result.WebInfo = structs
			}
		}
	}
	all, err := dao.Banalyze.Ctx(ctx).Where("1=?", 1).All()
	jsonBanalyze, err := TransToBanalyze(all)
	if err == nil && jsonBanalyze != nil {
		var exportData []*banalyze.App
		for _, v := range jsonBanalyze {
			jsonList, err := banalyze.LoadApps([]byte(v.Value))
			if err != nil {
				continue
			}
			exportData = append(exportData, jsonList.Apps[0])
		}
		result.Banalyze = exportData
	}

	return &result
}

// EmptyPort 端口扫描清空消息队列
func (s *serviceScanEngine) EmptyPort(ctx context.Context) error {
	return producer.EmptyNsqTopic(ctx, Gnsq.PortScanTopic, Gnsq.PortScanTopicChanl)
}

// EmptyDomain 子域名清空消息队列
func (s *serviceScanEngine) EmptyDomain(ctx context.Context) error {
	return producer.EmptyNsqTopic(ctx, Gnsq.SubDomainTopic, Gnsq.SubDomainChanl)
}

// EmptyWebInfo Web探测清空消息队列
func (s *serviceScanEngine) EmptyWebInfo(ctx context.Context) error {
	return producer.EmptyNsqTopic(ctx, Gnsq.WebInfoTopic, Gnsq.RWebInfoChanl)
}

// ManagerAdd 添加厂商
func (s *serviceScanEngine) ManagerAdd(ctx context.Context, r *model.ApiScanManagerAddReq) error {
	count, err := dao.ScanHome.Ctx(ctx).Where("cus_name=?", r.CusName).Count()
	if err != nil {
		logger.WebLog.Warningf(ctx, "综合扫描-添加厂商失败:%s", err.Error())
		return errors.New("添加厂商失败,数据库错误")
	}
	if count > 0 {
		return errors.New("添加厂商失败,已存在该厂商")
	}
	_, err = dao.ScanHome.Ctx(ctx).Insert(r)
	if err != nil {
		logger.WebLog.Warningf(ctx, "综合扫描-添加厂商失败:%s", err.Error())
		return errors.New("添加厂商失败,数据库错误")
	}
	return nil
}

func TransToApiKey(one gdb.Record) (*model.ApiKey, error) {
	var apikey *model.ApiKey
	if err := one.Struct(&apikey); err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	return apikey, nil
}

func TransToBanalyze(all gdb.Result) ([]*model.Banalyze, error) {
	var banalyzes []*model.Banalyze
	if err := all.Structs(&banalyzes); err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	return banalyzes, nil
}
