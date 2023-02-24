package config

import (
	"context"
	"fmt"
	"github.com/Rewriterl/ifgather-client/internal/logic/webinfo/banalyze"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"log"
	"time"
)

func init() {
	getConfigInfo()
}

// 从web服务器接受配置信息
type Config struct {
	Nsq      NsqInfo         `json:"nsq"`
	PortScan PortScanInfo    `json:"portscan"`
	Domain   DomainInfo      `json:"domain"`
	ApiKey   KeyInfo         `json:"apikey"`
	WebInfo  WebInfo         `json:"webinfo"`
	Banalyze []*banalyze.App `json:"banalyze"`
}

// Nsq配置
type NsqInfo struct {
	NsqHost string `json:"nsqd_host"`
	NsqHttp string `json:"nsqd_http"`
	Time    int    `json:"time"`
}

// 端口扫描配置
type PortScanInfo struct {
	Verify      bool   `json:"verify"`
	Ping        bool   `json:"ping"`
	Retries     int    `json:"retries"`
	Rate        int    `json:"rate"`
	Timeout     int    `json:"timeout"`
	Ports       string `json:"ports"`
	NmapTimeout int    `json:"nmap_timeout"`
	WafNum      int    `json:"waf_num"`
	Detection   string `json:"detection"`
	NsqTimeout  int    `json:"nsq_timeout"`
}

// 子域名探测配置
type DomainInfo struct {
	Timeout     int `json:"timeout"`
	MaxEnumTime int `json:"max_enum_time"`
	NsqTimeout  int `json:"nsq_timeout"`
}

// API 秘钥配置
type KeyInfo struct {
	Shodan         string `json:"shodan"`
	Binaryedge     string `json:"binaryedge"`
	CensysToken    string `json:"censys_token"`
	CensysSecret   string `json:"censys_secret"`
	Certspotter    string `json:"certspotter"`
	GitHub         string `json:"github"`
	Spyse          string `json:"spyse"`
	Securitytrails string `json:"securitytrails"`
	ThreatBook     string `json:"threatbook"`
	URLScan        string `json:"urlscan"`
	Virustotal     string `json:"virustotal"`
}

// web探测 配置
type WebInfo struct {
	WappalyzerTimeout int `json:"wappalyzertimeout"`
	SpiderTimeout     int `json:"spidertimeout"`
	MaxDepth          int `json:"maxdepth"`
	Concurrent        int `json:"concurrent"`
}

// 全局调用
var Gconf *Config

// 从Web服务器获取配置信息 初始化
func getConfigInfo() {
	ctx := context.Background()
	host := g.Cfg().MustGet(ctx, "server.host")
	port := g.Cfg().MustGet(ctx, "server.address")
	pwd := g.Cfg().MustGet(ctx, "server.password")
	url := fmt.Sprintf("http://%s%s/scan/client/info?pwd=%s", host, port, pwd)
	result, err := g.Client().Timeout(15*time.Second).Get(ctx, url)
	if err != nil {
		log.Fatal("同步配置信息失败,请检查能否访问Web服务器")
	}
	defer func() {
		if result != nil {
			_ = result.Close()
		}
	}()
	j, err := gjson.DecodeToJson(result.ReadAllString())
	if err != nil {
		log.Fatalf("同步配置信息失败,配置信息解析失败:%s", err.Error())
	}
	if err := j.Scan(&Gconf); err != nil {
		log.Fatalf("同步配置信息失败,配置信息反序列化失败:%s", err.Error())
	}
	log.Println("[+] 同步配置信息成功")
	go goGetInfo()
}

// 创建一个协程 用于不间断的更新配置信息
func goGetInfo() {
	for {
		time.Sleep(time.Duration(Gconf.Nsq.Time) * time.Minute)
		ctx := context.Background()
		host := g.Cfg().MustGet(ctx, "server.host")
		pwd := g.Cfg().MustGet(ctx, "server.password")
		url := fmt.Sprintf("http://%s/api/client/info?pwd=%s", host, pwd)
		result, err := g.Client().Timeout(15*time.Second).Get(ctx, url)
		if err != nil {
			continue
		}
		defer func() {
			if result != nil {
				_ = result.Close()
			}
		}()
		j, err := gjson.DecodeToJson(result.ReadAllString())
		if err != nil {
			continue
		}
		if err := j.Scan(&Gconf); err != nil {
			continue
		}
		log.Printf("[+] 定时同步配置信息成功,下一次在[%d]分钟后更新", Gconf.Nsq.Time)
	}
}
