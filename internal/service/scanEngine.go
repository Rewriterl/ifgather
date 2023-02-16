package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/Rewriterl/ifgather/internal/dao"
	"github.com/Rewriterl/ifgather/internal/model"
	"github.com/Rewriterl/ifgather/utility/banalyze"
	"github.com/Rewriterl/ifgather/utility/logger"
	Gnsq "github.com/Rewriterl/ifgather/utility/nsq"
	"github.com/Rewriterl/ifgather/utility/nsq/producer"
	"github.com/Rewriterl/ifgather/utility/nsq/pushmsg"
	"github.com/Rewriterl/ifgather/utility/tools"
	"github.com/gogf/gf/v2/container/gset"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/text/gstr"
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
	var jsonNsq *model.ApiKey
	err = tools.TransToStruct(one, &jsonNsq)
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
	var jsonPortScan *model.ApiKey
	err = tools.TransToStruct(one, &jsonPortScan)
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
	var jsonDomain *model.ApiKey
	err = tools.TransToStruct(one, &jsonDomain)
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
	var jsonApiKey *model.ApiKey
	err = tools.TransToStruct(one, &jsonApiKey)
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
	var jsonWebInfo *model.ApiKey
	err = tools.TransToStruct(one, &jsonWebInfo)
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
	var banalyzes []*model.Banalyze
	err = tools.TransToStructs(all, &banalyzes)
	if err == nil && banalyzes != nil {
		var exportData []*banalyze.App
		for _, v := range banalyzes {
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

// ManagerDelete 删除厂商
func (s *serviceScanEngine) ManagerDelete(ctx context.Context, r *model.ApiScanManagerDeleteReq) error {
	count, err := dao.ScanHome.Ctx(ctx).Where("cus_name=?", r.CusName).Count()
	if err != nil {
		logger.WebLog.Warningf(ctx, "综合扫描-删除厂商失败:%s", err.Error())
		return errors.New("删除厂商失败,数据库错误")
	}
	if count == 0 {
		return errors.New("删除厂商失败,该厂商不存在")
	}
	if _, err = dao.ScanHome.Ctx(ctx).Where("cus_name=?", r.CusName).Delete(); err != nil {
		return errors.New(fmt.Sprintf("删除厂商失败:%s", err.Error()))
	}
	if _, err = dao.ScanDomain.Ctx(ctx).Where("cus_name=?", r.CusName).Delete(); err != nil {
		return errors.New(fmt.Sprintf("删除厂商失败:%s", err.Error()))
	}
	if _, err = dao.ScanSubdomain.Ctx(ctx).Where("cus_name=?", r.CusName).Delete(); err != nil {
		return errors.New(fmt.Sprintf("删除厂商失败:%s", err.Error()))
	}
	if _, err = dao.ScanPort.Ctx(ctx).Where("cus_name=?", r.CusName).Delete(); err != nil {
		return errors.New(fmt.Sprintf("删除厂商失败:%s", err.Error()))
	}
	if _, err = dao.ScanWeb.Ctx(ctx).Where("cus_name=?", r.CusName).Delete(); err != nil {
		return errors.New(fmt.Sprintf("删除厂商失败:%s", err.Error()))
	}
	return nil
}

// SearchManager 厂商模糊搜索分页查询
func (s *serviceScanEngine) SearchManager(ctx context.Context, page, limit int, search interface{}) *model.ResAPiScanManager {
	var (
		result []*model.ScanHome
	)
	SearchModel := dao.ScanHome.Ctx(ctx).Clone()
	searchStr := gconv.String(search)
	if search != "" {
		j := gjson.New(searchStr)
		if gconv.String(j.Get("CusName")) != "" {
			SearchModel = SearchModel.Where("cus_name like ?", "%"+gconv.String(j.Get("CusName"))+"%")
		}
	}
	count, _ := SearchModel.Count()
	if page > 0 && limit > 0 {
		err := SearchModel.Order("id desc").Limit((page-1)*limit, limit).Scan(&result)
		if err != nil {
			logger.WebLog.Warningf(ctx, "厂商管理分页查询 数据库错误:%s", err.Error())
			return &model.ResAPiScanManager{Code: 201, Msg: "查询失败,数据库错误", Count: 0, Data: nil}
		}
	} else {
		return &model.ResAPiScanManager{Code: 201, Msg: "查询失败,分页参数有误", Count: 0, Data: nil}
	}
	results := make([]model.ResAPiScanManagerInfo, 0)
	for i, _ := range result {
		subCount, _ := dao.ScanSubdomain.Ctx(ctx).Where("cus_name=?", result[i].CusName).Count()
		portCount, _ := dao.ScanPort.Ctx(ctx).Where("cus_name=?", result[i].CusName).Count()
		urlCount, _ := dao.ScanWeb.Ctx(ctx).Where("cus_name=?", result[i].CusName).Count()
		results = append(results, model.ResAPiScanManagerInfo{
			Id:              result[i].Id,
			CusName:         result[i].CusName,
			CusTime:         result[i].CreateAt,
			CusSudDomainNum: subCount,
			CusPortNum:      portCount,
			CusWebNum:       urlCount,
		})
	}
	return &model.ResAPiScanManager{Code: 0, Msg: "ok", Count: int64(count), Data: results}
}

// AddDomain 添加主域名
func (s *serviceScanEngine) AddDomain(ctx context.Context, r *model.ScanDomainApiAddReq) error {
	type ScanDomain struct {
		Domain string `v:"domain#主域名不正确"`
	}
	count, err := dao.ScanHome.Ctx(ctx).Where("cus_name=?", r.CusName).Count()
	if err != nil {
		logger.WebLog.Warningf(ctx, "综合扫描-添加主域名失败:%s", err.Error())
		return errors.New("添加主域名失败,数据库错误")
	}
	if count == 0 {
		return errors.New("添加主域名失败,该厂商不存在")
	}
	strList := gstr.Split(r.Domain, "\n")
	domainList := gset.NewStrSet()
	returnErr := errors.New("添加主域名失败,无有效数据")
	if len(strList) == 0 {
		return returnErr
	}
	for _, tmp := range strList {
		domain := gstr.Trim(tmp)
		if domain == "" {
			continue
		}
		if e := g.Validator().Data(ScanDomain{Domain: domain}).Run(ctx); e != nil { // 校检domain
			return errors.New(e.Error())
		}
		domainList.Add(domain)
	}
	if domainList.Size() == 0 {
		return returnErr
	}
	all, err := dao.ScanDomain.Ctx(ctx).Where("1=?", 1).All()
	if err != nil {
		return returnErr
	}
	var scanDomains []*model.ScanDomain
	err = tools.TransToStructs(all, &scanDomains)
	if err != nil {
		return returnErr
	}
	for _, v := range scanDomains {
		if domainList.ContainsI(v.Domain) {
			domainList.Remove(v.Domain)
		}
	}
	if domainList.Size() == 0 {
		return returnErr
	}
	logger.WebLog.Debugf(ctx, "添加主域名成功，共:%d个 %+v", domainList.Size(), domainList.String())
	for _, domain := range domainList.Slice() {
		_, err = dao.ScanDomain.Ctx(ctx).Insert(g.Map{
			"CusName": r.CusName,
			"Domain":  domain,
			"Flag":    false,
			"NsqFlag": false,
		})
		if err != nil {
			logger.WebLog.Warningf(ctx, "添加主域名 插入数据库错误:%s", err.Error())
			continue
		}
	}
	go pushmsg.PushDomain(ctx, r.CusName)
	return nil
}

// SearchDomain 主域名模糊搜索分页查询
func (s *serviceScanEngine) SearchDomain(ctx context.Context, page, limit int, search interface{}) *model.ResAPiScanDomain {
	var (
		result []*model.ScanDomain
	)
	SearchModel := dao.ScanDomain.Ctx(ctx).Clone()
	searchStr := gconv.String(search)
	if search != "" {
		j := gjson.New(searchStr)
		if gconv.String(j.Get("CusName")) != "" {
			SearchModel = SearchModel.Where("cus_name like ?", "%"+gconv.String(j.Get("CusName"))+"%")
		}
		if gconv.String(j.Get("Domain")) != "" {
			SearchModel = SearchModel.Where("domain like ?", "%"+gconv.String(j.Get("Domain"))+"%")
		}
	}
	count, _ := SearchModel.Count()
	if page > 0 && limit > 0 {
		err := SearchModel.Order("id desc").Limit((page-1)*limit, limit).Scan(&result)
		if err != nil {
			logger.WebLog.Warningf(ctx, "主域名管理分页查询 数据库错误:%s", err.Error())
			return &model.ResAPiScanDomain{Code: 201, Msg: "查询失败,数据库错误", Count: 0, Data: nil}
		}
	} else {
		return &model.ResAPiScanDomain{Code: 201, Msg: "查询失败,分页参数有误", Count: 0, Data: nil}
	}
	return &model.ResAPiScanDomain{Code: 0, Msg: "ok", Count: int64(count), Data: result}
}

// GetApiCusName 返回Group厂商数据
func (s *serviceScanEngine) GetApiCusName(ctx context.Context, page, limit int, search interface{}) *model.ResAPiScanCusNames {
	var (
		result []model.ScanHome
	)
	SearchModel := dao.ScanHome.Ctx(ctx).Clone()
	searchStr := gconv.String(search)
	if searchStr != "" {
		SearchModel = SearchModel.Where("cus_name like ?", "%"+searchStr+"%")
	}
	count, _ := SearchModel.Count()
	if page > 0 && limit > 0 {
		err := SearchModel.Order("id desc").Limit((page-1)*limit, limit).Scan(&result)
		if err != nil {
			return &model.ResAPiScanCusNames{Code: 201, Msg: "查询失败,数据库错误", Count: 0, Data: nil}
		}
	} else {
		return &model.ResAPiScanCusNames{Code: 201, Msg: "查询失败,分页参数有误", Count: 0, Data: nil}
	}
	return &model.ResAPiScanCusNames{Code: 0, Msg: "ok", Count: int64(count), Data: result}
}
