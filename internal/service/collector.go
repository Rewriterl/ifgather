package service

import (
	"context"
	"errors"
	"github.com/Rewriterl/ifgather/internal/dao"
	"github.com/Rewriterl/ifgather/internal/model"
	"github.com/Rewriterl/ifgather/utility/logger"
	"github.com/Rewriterl/ifgather/utility/nsq/producer"
	"github.com/Rewriterl/ifgather/utility/tools"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/text/gstr"
	"github.com/gogf/gf/v2/util/gconv"
)

var Collector = new(collectorService)

type collectorService struct{}

// AddSubDomain 添加子域名扫描任务
func (s *collectorService) AddSubDomain(ctx context.Context, r *model.ScanDomainApiAddReq) error {
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

// SearchSubDomainManager 子域名扫描任务模糊分页查询
func (s *collectorService) SearchSubDomainManager(ctx context.Context, page, limit int, search interface{}) *model.UtilSubDomainTaskApiManager {
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
