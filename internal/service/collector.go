package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Rewriterl/ifgather/internal/dao"
	"github.com/Rewriterl/ifgather/internal/model"
	"github.com/Rewriterl/ifgather/utility/banalyze"
	"github.com/Rewriterl/ifgather/utility/logger"
	"github.com/Rewriterl/ifgather/utility/nsq/producer"
	"github.com/Rewriterl/ifgather/utility/tools"
	"github.com/gogf/gf/v2/container/gset"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/text/gstr"
	"github.com/gogf/gf/v2/util/gconv"
	"github.com/projectdiscovery/ipranger"
	"strings"
)

var Collector = new(collectorService)

type collectorService struct{}

// AddSubDomainTask 添加子域名扫描任务
func (s *collectorService) AddSubDomainTask(ctx context.Context, r *model.ScanDomainApiAddReq) error {
	strList := gstr.Split(r.Domain, "\n")
	domainList := make([]string, 0)
	if len(strList) == 0 {
		return errors.New("添加主域名失败,无有效数据")
	}
	for _, tmp := range strList {
		domain := gstr.Trim(tmp)
		if domain == "" {
			continue
		}
		if e := g.Validator().Data(tools.ScanDomain{Domain: domain}).Run(ctx); e != nil { // 校检domain
			return errors.New(e.Error())
		}
		domainList = append(domainList, domain)
	}
	if len(domainList) == 0 {
		return errors.New("添加主域名失败,无有效数据")
	}
	// 任务信息保存到数据库中
	if result, err := dao.UtilSubdomainTask.Ctx(ctx).Where("cus_name=?", r.CusName).One(); err != nil {
		return errors.New("添加子域名扫描任务失败,数据库错误")
	} else if result == nil {
		if _, err = dao.UtilSubdomainTask.Ctx(ctx).Insert(g.Map{"cus_name": r.CusName, "domain_num": len(domainList), "scan_num": 0}); err != nil {
			return errors.New("添加子域名扫描任务失败,数据库错误")
		}
	} else {
		var domainTask *model.UtilSubdomainTask
		err := tools.TransToStruct(result, &domainTask)
		if _, err = dao.UtilSubdomainTask.Ctx(ctx).Update(g.Map{"domain_num": domainTask.DomainNum + len(domainList)}, "cus_name", r.CusName); err != nil {
			return errors.New("添加子域名扫描任务失败,数据库错误")
		}
	}
	logger.WebLog.Debugf(ctx, "Util-添加主域名成功，共:%d个 %+v", len(domainList), domainList)
	pubMessages := make([]model.ScanDomainApiAddReq, 0)
	for _, k := range domainList {
		pubMessages = append(pubMessages, model.ScanDomainApiAddReq{CusName: "util-" + r.CusName, Domain: k})
	}
	go producer.PushSubDomain(ctx, pubMessages)
	return nil
}

// SearchSubDomainTask 模糊分页查询子域名扫描任务
func (s *collectorService) SearchSubDomainTask(ctx context.Context, page, limit int, search interface{}) *model.UtilSubDomainTaskApiManager {
	var (
		result []*model.UtilSubdomainTask
	)
	SearchModel := dao.UtilSubdomainTask.Ctx(ctx).Clone()
	searchStr := gconv.String(search)
	if search != "" {
		j := gjson.New(searchStr)
		if gconv.String(j.Get("taskname")) != "" {
			SearchModel = SearchModel.Ctx(ctx).Where("cus_name like ?", "%"+gconv.String(j.Get("taskname"))+"%")
		}
	}
	count, _ := SearchModel.Ctx(ctx).Count()
	if page > 0 && limit > 0 {
		err := SearchModel.Ctx(ctx).Order("id desc").Limit((page-1)*limit, limit).Scan(&result)
		if err != nil {
			logger.WebLog.Warningf(ctx, "Util-子域名扫描管理分页查询 数据库错误:%s", err.Error())
			return &model.UtilSubDomainTaskApiManager{Code: 201, Msg: "查询失败,数据库错误", Count: 0, Data: nil}
		}
	} else {
		return &model.UtilSubDomainTaskApiManager{Code: 201, Msg: "查询失败,分页参数有误", Count: 0, Data: nil}
	}
	return &model.UtilSubDomainTaskApiManager{Code: 0, Msg: "ok", Count: int64(count), Data: result}
}

// SearchSubDomainDetails 模糊分页查询子域名扫描详情
func (s *collectorService) SearchSubDomainDetails(ctx context.Context, page, limit int, cus_name string, search interface{}) *model.ScanSubdomainRes {
	var (
		result []*model.ScanSubdomain
	)
	SearchModel := dao.UtilSubdomainResult.Ctx(ctx).Clone()
	SearchModel = SearchModel.Ctx(ctx).Where("cus_name=?", cus_name)
	searchStr := gconv.String(search)
	if search != "" {
		j := gjson.New(searchStr)
		if gconv.String(j.Get("IP")) != "" {
			SearchModel = SearchModel.Ctx(ctx).Where("ip like ?", "%"+gconv.String(j.Get("IP"))+"%")
		}
		if gconv.String(j.Get("Location")) != "" {
			SearchModel = SearchModel.Ctx(ctx).Where("location like ?", "%"+gconv.String(j.Get("Location"))+"%")
		}
		if gconv.String(j.Get("SubDomain")) != "" {
			SearchModel = SearchModel.Ctx(ctx).Where("subdomain like ?", "%"+gconv.String(j.Get("SubDomain"))+"%")
		}
	}
	count, _ := SearchModel.Ctx(ctx).Count()
	if page > 0 && limit > 0 {
		err := SearchModel.Ctx(ctx).Limit((page-1)*limit, limit).Scan(&result)
		if err != nil {
			logger.WebLog.Warningf(ctx, "Util-子域名分页查询 数据库错误:%s", err.Error())
			return &model.ScanSubdomainRes{Code: 201, Msg: "查询失败,数据库错误", Count: 0, Data: nil}
		}
	} else {
		return &model.ScanSubdomainRes{Code: 201, Msg: "查询失败,分页参数有误", Count: 0, Data: nil}
	}
	return &model.ScanSubdomainRes{Code: 0, Msg: "ok", Count: int64(count), Data: result}
}

// DelSubDomainTask 删除指定子域名扫描任务
func (s *collectorService) DelSubDomainTask(ctx context.Context, r *model.UtilSubdomainTaskDelReq) error {
	res, err := dao.UtilSubdomainTask.Ctx(ctx).Delete("cus_name=?", r.CusName)
	if err != nil {
		return errors.New("删除该任务失败,数据库错误")
	} else if res == nil {
		return errors.New("删除该任务失败,数据库中无此任务")
	}
	_, err = dao.UtilSubdomainResult.Ctx(ctx).Delete("cus_name=?", r.CusName)
	return nil
}

// EmptySubDomainTask 清空子域名扫描任务
func (s *collectorService) EmptySubDomainTask(ctx context.Context) error {
	if _, err := dao.UtilSubdomainTask.Ctx(ctx).Delete("1=1"); err != nil {
		logger.WebLog.Warningf(ctx, "清空Util-子域名扫描数据 数据库错误:%s", err.Error())
		return errors.New("清空子域名数据失败,数据库错误")
	}
	if _, err := dao.UtilSubdomainResult.Ctx(ctx).Delete("1=1"); err != nil {
		logger.WebLog.Warningf(ctx, "清空util-子域名扫描数据 数据库错误:%s", err.Error())
		return errors.New("清空子域名数据失败,数据库错误")
	}
	return nil
}

// AddPortScanTask 添加端口扫描任务
func (s *collectorService) AddPortScanTask(ctx context.Context, r *model.UtilPortScanApiAddReq) (string, error) {
	// 检测待扫描端口 参数值是否正确
	if r.Ports != "full" && r.Ports != "top100" && r.Ports != "top1000" && !strings.Contains(r.Ports, "-") &&
		!strings.Contains(r.Ports, ",") && !gstr.IsNumeric(r.Ports) {
		return "", errors.New("待扫描端口ports参数格式错误,请检查")
	}

	// 解析hosts参数值
	hostlist := strings.Split(r.Hosts, "\n")
	IpSet := gset.NewStrSet() // 保存解析的host并去重
	// 提取解析host
	if len(hostlist) == 1 { // 单条记录
		if !ipranger.IsCidr(r.Hosts) && !ipranger.IsIP(r.Hosts) { // 判断提交的host格式是否正确
			return "", errors.New("提交的主机地址格式有误,请检查")
		} else if ipranger.IsIP(r.Hosts) {
			IpSet.Add(gstr.Trim(r.Hosts))
		} else {
			iplist, err := ipranger.Ips(r.Hosts)
			if err != nil {
				return "", errors.New("提交的主机地址格式有误,请检查")
			} else {
				IpSet.Add(iplist...)
			}
		}
	} else { // 多条记录
		for _, tmphost := range hostlist {
			if gstr.Trim(tmphost) == "" {
				continue
			}
			if !ipranger.IsCidr(tmphost) && !ipranger.IsIP(tmphost) {
				return "", errors.New("提交的主机地址格式有误,请检查")
			} else if ipranger.IsIP(tmphost) {
				IpSet.Add(gstr.Trim(tmphost))
			} else {
				iplist, err := ipranger.Ips(tmphost)
				if err != nil {
					return "", errors.New("提交的主机地址格式有误,请检查")
				} else {
					IpSet.Add(iplist...)
				}
			}
		}
	}

	if IpSet.Size() == 0 {
		return "", errors.New("解析后的host主机数为0个,请检查")
	}

	// 任务信息保存到数据库中
	if result, err := dao.UtilPortscanTask.Ctx(ctx).Where("cus_name=?", r.CusName).One(); err != nil {
		return "", errors.New("添加端口扫描任务失败,数据库错误")
	} else if result == nil {
		if result, err := dao.UtilPortscanTask.Ctx(ctx).Insert(g.Map{"cus_name": r.CusName, "host_num": IpSet.Size(), "scan_num": 0}); err != nil {
			return "", errors.New("添加端口扫描任务失败,数据库错误")
		} else if result == nil {
			return "", errors.New("添加端口扫描任务失败,数据库插入数据失败")
		}
	} else {
		var portScanTask *model.UtilPortscanTask
		_ = tools.TransToStruct(result, &portScanTask)
		if res, err := dao.UtilPortscanTask.Ctx(ctx).Update(g.Map{"host_num": portScanTask.HostNum + IpSet.Size()}, "cus_name", r.CusName); err != nil {
			return "", errors.New("添加端口扫描任务失败,数据库错误")
		} else if res == nil {
			return "", errors.New("添加端口扫描任务失败,数据库更新数据失败")
		}
	}

	logger.WebLog.Debugf(ctx, "util-添加端口扫描任务[%s]成功, 共计[%d]台主机", r.CusName, IpSet.Size())
	// 批量发送到消息队列中
	SendMsg := make([]model.UtilPortScanApiAddReq, 0)

	r.CusName = "util-" + r.CusName
	for _, addres := range IpSet.Slice() {
		tmpmsg := *r
		tmpmsg.Hosts = addres
		SendMsg = append(SendMsg, tmpmsg)
	}
	// 异步投递消息
	go producer.SendPortScanMessage(ctx, SendMsg)
	return fmt.Sprintf("util-添加端口扫描任务成功,共计:%d台主机", IpSet.Size()), nil
}

// SearchPortScanTask 端口扫描任务模糊分页查询
func (s *collectorService) SearchPortScanTask(ctx context.Context, page, limit int, search interface{}) *model.UtilPortScanResManager {
	var (
		result []*model.UtilPortscanTask
	)
	SearchModel := dao.UtilPortscanTask.Ctx(ctx).Clone() // 链式操作
	searchStr := gconv.String(search)
	if search != "" {
		j := gjson.New(searchStr)
		if gconv.String(j.Get("cusname")) != "" {
			SearchModel = SearchModel.Where("cus_name like ?", "%"+gconv.String(j.Get("cusname"))+"%")
		}
	}
	count, _ := SearchModel.Ctx(ctx).Count()
	if page > 0 && limit > 0 {
		err := SearchModel.Ctx(ctx).Order("id desc").Limit((page-1)*limit, limit).Scan(&result)
		if err != nil {
			logger.WebLog.Warningf(ctx, "端口扫描管理分页查询 数据库错误:%s", err.Error())
			return &model.UtilPortScanResManager{Code: 201, Msg: "查询失败,数据库错误", Count: 0, Data: nil}
		}
	} else {
		return &model.UtilPortScanResManager{Code: 201, Msg: "查询失败,分页参数有误", Count: 0, Data: nil}
	}
	return &model.UtilPortScanResManager{Code: 0, Msg: "ok", Count: int64(count), Data: result}
}

// DelPortScanTask 端口扫描删除指定任务(数据库)
func (s *collectorService) DelPortScanTask(ctx context.Context, r *model.UtilSubdomainTaskDelReq) error {
	res, err := dao.UtilPortscanTask.Ctx(ctx).Delete("cus_name=?", r.CusName)
	if err != nil {
		return errors.New("删除该任务失败,数据库错误")
	} else if res == nil {
		return errors.New("删除该任务失败,数据库中无此任务")
	}
	_, _ = dao.UtilPortscanResult.Ctx(ctx).Delete("cus_name=?", r.CusName)
	return nil
}

// EmptyPortScanTask 清空全部端口扫描任务
func (s *collectorService) EmptyPortScanTask(ctx context.Context) error {
	if _, err := dao.UtilPortscanTask.Ctx(ctx).Delete("1=1"); err != nil {
		logger.WebLog.Warningf(ctx, "清空util-端口扫描数据 数据库错误:%s", err.Error())
		return err
	}
	if _, err := dao.UtilPortscanResult.Ctx(ctx).Delete("1=1"); err != nil {
		logger.WebLog.Warningf(ctx, "清空util-端口扫描数据 数据库错误:%s", err.Error())
		return err
	}
	return nil
}

// SearchPortScanDetails 端口扫描详情模糊分页查询
func (s *collectorService) SearchPortScanDetails(ctx context.Context, page, limit int, task_name string, search interface{}) *model.UtilPortScanResultRes {
	var (
		result []*model.UtilPortscanResult
	)
	SearchModel := dao.UtilPortscanResult.Ctx(ctx).Clone() // 链式操作
	SearchModel = SearchModel.Ctx(ctx).Where("cus_name=?", task_name)
	searchStr := gconv.String(search)
	if search != "" {
		j := gjson.New(searchStr)
		if gconv.String(j.Get("host")) != "" {
			SearchModel = SearchModel.Ctx(ctx).Where("host like ?", "%"+gconv.String(j.Get("host"))+"%")
		}
		if gconv.String(j.Get("port")) != "" {
			SearchModel = SearchModel.Ctx(ctx).Where("port = ?", gconv.String(j.Get("port")))
		}
		if gconv.String(j.Get("servicename")) != "" {
			SearchModel = SearchModel.Ctx(ctx).Where("service_name like ?", "%"+gconv.String(j.Get("servicename"))+"%")
		}
		if gconv.String(j.Get("title")) != "" {
			SearchModel = SearchModel.Ctx(ctx).Where("title like ?", "%"+gconv.String(j.Get("title"))+"%")
		}
		if gconv.String(j.Get("url")) != "" {
			SearchModel = SearchModel.Ctx(ctx).Where("url like ?", "%"+gconv.String(j.Get("url"))+"%")
		}
	}
	count, _ := SearchModel.Ctx(ctx).Count()
	if page > 0 && limit > 0 {
		err := SearchModel.Ctx(ctx).Limit((page-1)*limit, limit).Scan(&result)
		if err != nil {
			logger.WebLog.Warningf(ctx, "端口扫描管理分页查询 数据库错误:%s", err.Error())
			return &model.UtilPortScanResultRes{Code: 201, Msg: "查询失败,数据库错误", Count: 0, Data: nil}
		}
	} else {
		return &model.UtilPortScanResultRes{Code: 201, Msg: "查询失败,分页参数有误", Count: 0, Data: nil}
	}
	return &model.UtilPortScanResultRes{Code: 0, Msg: "ok", Count: int64(count), Data: result}
}

func (s *collectorService) GetPortScanEchartsInfo(ctx context.Context, TaskName string) interface{} {
	var result1 []model.UtilPortScanResultResEchartsInfos
	var result2 []model.UtilPortScanResultResEchartsInfos1
	err := dao.UtilPortscanResult.Ctx(ctx).Fields("COUNT(service_name) Number, service_name").
		Where("cus_name=?", TaskName).Group("service_name").Limit(10).Scan(&result1)
	if err != nil {
		return nil
	}
	err = dao.UtilPortscanResult.Ctx(ctx).Fields("COUNT(port) Number, port").
		Where("cus_name=?", TaskName).Group("port").Limit(10).Scan(&result2)
	if err != nil {
		return nil
	}
	return &model.UtilPortScanResultResEchartsInfo{Code: 200, Msg: "ok", Data: result1, Data1: result2}
}

// SearchBanalyze web模糊分页查询指纹扫描任务
func (s *collectorService) SearchBanalyze(ctx context.Context, page, limit int, search interface{}) *model.BanalyzeAPiManager {
	var (
		result []*model.Banalyze
	)
	SearchModel := dao.Banalyze.Ctx(ctx).Clone() // 链式操作
	searchStr := gconv.String(search)
	if search != "" {
		j := gjson.New(searchStr)
		if gconv.String(j.Get("key")) != "" {
			SearchModel = SearchModel.Ctx(ctx).Where("key like ?", "%"+gconv.String(j.Get("key"))+"%")
		}
		if gconv.String(j.Get("description")) != "" {
			SearchModel = SearchModel.Ctx(ctx).Where("description like ?", "%"+gconv.String(j.Get("description"))+"%")
		}
	}
	count, _ := SearchModel.Ctx(ctx).Count()
	if page > 0 && limit > 0 {
		err := SearchModel.Ctx(ctx).Order("id desc").Limit((page-1)*limit, limit).Scan(&result)
		if err != nil {
			logger.WebLog.Warningf(ctx, "web指纹管理分页查询 数据库错误:%s", err.Error())
			return &model.BanalyzeAPiManager{Code: 201, Msg: "查询失败,数据库错误", Count: 0, Data: nil}
		}
	} else {
		return &model.BanalyzeAPiManager{Code: 201, Msg: "查询失败,分页参数有误", Count: 0, Data: nil}
	}
	return &model.BanalyzeAPiManager{Code: 0, Msg: "ok", Count: int64(count), Data: result}
}

// EmptyBanalyze 清空所有web指纹数据
func (s *collectorService) EmptyBanalyze(ctx context.Context) error {
	if _, err := dao.Banalyze.Ctx(ctx).Delete("1=1"); err != nil {
		logger.WebLog.Warningf(ctx, "清空web指纹失败 数据库错误:%s", err.Error())
		return err
	}
	return nil
}

// AddBanalyze 添加指纹
func (s *collectorService) AddBanalyze(ctx context.Context, r string) (string, error) {
	Wappalyzer, err := banalyze.LoadApps([]byte(r))
	if err != nil {
		logger.WebLog.Warningf(ctx, "指纹json数据解析失败:%s", err.Error())
		return "", errors.New("JSON数据解析失败,请检查")
	}
	if len(Wappalyzer.Apps) != 1 {
		return "", errors.New("只允许提交单条指纹")
	}
	banalyzeName := Wappalyzer.Apps[0].Name
	banalyzeWebsite := Wappalyzer.Apps[0].Website
	banalyzeDescription := Wappalyzer.Apps[0].Description
	if strings.Trim(banalyzeName, " ") == "" || strings.Trim(banalyzeWebsite, " ") == "" || strings.Trim(banalyzeDescription, " ") == "" {
		return "", errors.New("缺少必须参数字段,请检查")
	}
	count, err := dao.Banalyze.Ctx(ctx).Where("key=?", banalyzeName).Count()
	if err != nil {
		return "", errors.New("数据库查询错误")
	}
	if count > 0 {
		return "", errors.New("该指纹名数据库已存在,请更换指纹名")
	}
	result, err := Wappalyzer.Analyze(banalyzeWebsite, 10)
	if err != nil {
		return "", errors.New("指纹识别错误,请检查url是否能访问等问题")
	}
	if len(result) == 0 {
		return "", errors.New("指纹识别无匹配结果,请检查")
	}
	_, err = dao.Banalyze.Ctx(ctx).Insert(g.Map{"key": banalyzeName, "description": banalyzeDescription, "value": r})
	if err != nil {
		return "", errors.New("指纹识别成功,但插入到数据库失败")
	}
	mjson, err := json.Marshal(result)
	if err != nil {
		return "", errors.New("指纹识别成功,json序列化失败")
	}
	msg := fmt.Sprintf("指纹识别成功:\n%s", string(mjson))
	return msg, nil
}

// DelBanalyze 删除指定指纹
func (s *collectorService) DelBanalyze(ctx context.Context, r *model.BanalyzeAPiDeteleReq) error {
	_, err := dao.Banalyze.Ctx(ctx).Delete(g.Map{"key": r.Key})
	if err != nil {
		return err
	} else {
		return nil
	}
}

// SearchBanalyzeDetails 查看指定指纹
func (s *collectorService) SearchBanalyzeDetails(ctx context.Context, r *model.BanalyzeAPiDeteleReq) (string, error) {
	one, err := dao.Banalyze.Ctx(ctx).Where("key=?", r.Key).One()
	if one == nil {
		return "", errors.New("指纹不存在")
	}
	var ba *model.Banalyze
	_ = tools.TransToStruct(one, &ba)
	if err != nil {
		return "", err
	}
	return ba.Value, nil
}

// UpdateBanalyze 修改指纹
func (s *collectorService) UpdateBanalyze(ctx context.Context, r string) (string, error) {
	Wappalyzer, err := banalyze.LoadApps([]byte(r))
	if err != nil {
		logger.WebLog.Warningf(ctx, "指纹json数据解析失败:%s", err.Error())
		return "", errors.New("JSON数据解析失败,请检查")
	}
	if len(Wappalyzer.Apps) != 1 {
		return "", errors.New("只允许提交单条指纹")
	}
	banalyzeName := Wappalyzer.Apps[0].Name
	banalyzeWebsite := Wappalyzer.Apps[0].Website
	banalyzeDescription := Wappalyzer.Apps[0].Description
	if strings.Trim(banalyzeName, " ") == "" || strings.Trim(banalyzeWebsite, " ") == "" || strings.Trim(banalyzeDescription, " ") == "" {
		return "", errors.New("缺少必须参数字段,请检查")
	}
	count, err := dao.Banalyze.Ctx(ctx).Where("key=?", banalyzeName).Count()
	if err != nil {
		return "", errors.New("数据库查询错误")
	}
	if count == 0 {
		return "", errors.New("该指纹名数据库不存在，请检查")
	}
	result, err := Wappalyzer.Analyze(banalyzeWebsite, 10)
	if err != nil {
		return "", errors.New("指纹识别错误,请检查url是否能访问等问题")
	}
	if len(result) == 0 {
		return "", errors.New("指纹识别无匹配结果,请检查")
	}
	_, err = dao.Banalyze.Ctx(ctx).Update(g.Map{"description": banalyzeDescription, "value": r}, "key", banalyzeName)
	if err != nil {
		return "", errors.New("指纹识别成功,但更新数据失败")
	}
	mjson, err := json.Marshal(result)
	if err != nil {
		return "", errors.New("指纹识别成功,json序列化失败")
	}
	msg := fmt.Sprintf("指纹识别成功:\n%s", string(mjson))
	return msg, nil
}

// ExecBanalyzeScan 进行指纹识别
func (s *collectorService) ExecBanalyzeScan(ctx context.Context, search interface{}) *model.ResAPiUtilBanalyzeInfo {
	searchStr := gconv.String(search)
	if searchStr == "" {
		return &model.ResAPiUtilBanalyzeInfo{Code: 201, Msg: "请提交URL进行指纹识别", Count: 0, Data: nil}
	}
	j := gjson.New(searchStr)
	if gconv.String(j.Get("url")) == "" {
		return &model.ResAPiUtilBanalyzeInfo{Code: 201, Msg: "请提交URL进行指纹识别", Count: 0, Data: nil}
	}
	url := gconv.String(j.Get("url"))
	all, err := dao.Banalyze.Ctx(ctx).Where("1=?", 1).All()
	var banalyzes []*model.Banalyze
	if err != nil {
		return &model.ResAPiUtilBanalyzeInfo{Code: 201, Msg: "指纹识别失败,数据库查询指纹错误", Count: 0, Data: nil}
	}
	var exportData []*banalyze.App
	_ = tools.TransToStructs(all, &banalyzes)
	for _, v := range banalyzes {
		jsonList, err := banalyze.LoadApps([]byte(v.Value))
		if err != nil {
			continue
		}
		exportData = append(exportData, jsonList.Apps[0])
	}
	if len(exportData) == 0 {
		return &model.ResAPiUtilBanalyzeInfo{Code: 201, Msg: "指纹识别失败,无有效指纹库", Count: 0, Data: nil}
	}
	data, err := json.Marshal(exportData)
	if err != nil {
		return &model.ResAPiUtilBanalyzeInfo{Code: 201, Msg: "指纹识别失败,json序列化失败", Count: 0, Data: nil}
	}
	Wappalyzer, err := banalyze.LoadApps(data)
	if err != nil {
		return &model.ResAPiUtilBanalyzeInfo{Code: 201, Msg: "指纹识别失败,JSON反序列化失败", Count: 0, Data: nil}
	}
	result1, err := Wappalyzer.Analyze(url, 10)
	if err != nil {
		return &model.ResAPiUtilBanalyzeInfo{Code: 201, Msg: "指纹识别失败,请检查url是否能访问", Count: 0, Data: nil}
	}
	var resultData []*model.ResultApp
	index := 1
	for _, v := range result1 {
		resultData = append(resultData, &model.ResultApp{
			Id:          index,
			Name:        v.Name,
			Version:     strings.Join(v.Version, "\n"),
			Implies:     strings.Join(v.Implies, ","),
			Description: v.Description,
		})
		index++
	}
	return &model.ResAPiUtilBanalyzeInfo{Code: 0, Msg: "ok", Count: int64(len(result1)), Data: resultData}
}
