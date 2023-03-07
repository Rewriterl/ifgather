package passive

import (
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/alienvault"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/anubis"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/archiveis"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/binaryedge"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/bufferover"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/cebaidu"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/censys"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/certspotter"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/certspotterold"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/commoncrawl"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/crtsh"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/dnsdb"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/dnsdumpster"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/github"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/hackertarget"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/intelx"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/ipv4info"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/passivetotal"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/rapiddns"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/recon"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/riddler"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/robtex"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/securitytrails"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/shodan"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/sitedossier"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/sonarsearch"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/spyse"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/sublist3r"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/threatbook"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/threatcrowd"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/threatminer"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/virustotal"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/waybackarchive"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/ximcx"
	"github.com/Rewriterl/ifgather-client/internal/logic/domain/subfinder/subscraping/sources/zoomeye"
)

// DefaultSources 包含默认使用的源列表。
var DefaultSources = []string{
	"alienvault",
	"anubis",
	"bufferover",
	"cebaidu",
	"certspotter",
	"certspotterold",
	"censys",
	"crtsh",
	"dnsdumpster",
	"hackertarget",
	"intelx",
	"ipv4info",
	"passivetotal",
	"robtex",
	"riddler",
	"securitytrails",
	"shodan",
	"spyse",
	"sublist3r",
	"threatcrowd",
	"threatminer",
	"virustotal",
	"binaryedge",
}

// DefaultRecursiveSources 包含默认递归源的列表
var DefaultRecursiveSources = []string{
	"alienvault",
	"binaryedge",
	"bufferover",
	"cebaidu",
	"certspotter",
	"certspotterold",
	"crtsh",
	"dnsdumpster",
	"hackertarget",
	"ipv4info",
	"passivetotal",
	"securitytrails",
	"sonarsearch",
	"sublist3r",
	"virustotal",
	"ximcx",
}

// DefaultAllSources 包含所有来源的列表
var DefaultAllSources = []string{
	"alienvault",
	"anubis",
	"archiveis",
	"binaryedge",
	"bufferover",
	"cebaidu",
	"censys",
	"certspotter",
	"certspotterold",
	"chaos",
	"commoncrawl",
	"crtsh",
	"dnsdumpster",
	"dnsdb",
	"github",
	"hackertarget",
	"ipv4info",
	"intelx",
	"passivetotal",
	"rapiddns",
	"riddler",
	"recon",
	"robtex",
	"securitytrails",
	"shodan",
	"sitedossier",
	"sonarsearch",
	"spyse",
	"sublist3r",
	"threatbook",
	"threatcrowd",
	"threatminer",
	"virustotal",
	"waybackarchive",
	"ximcx",
	"zoomeye",
}

// Agent 是用于运行被动子域枚举的结构
type Agent struct {
	sources map[string]subscraping.Source
}

// New 创建用于被动子域发现的新代理
func New(sources []string) *Agent {
	agent := &Agent{sources: make(map[string]subscraping.Source)}
	agent.addSources(sources)
	return agent
}

// addSources 将给定源列表添加到源数组
func (a *Agent) addSources(sources []string) {
	for _, source := range sources {
		switch source {
		case "alienvault":
			a.sources[source] = &alienvault.Source{}
		case "anubis":
			a.sources[source] = &anubis.Source{}
		case "archiveis":
			a.sources[source] = &archiveis.Source{}
		case "binaryedge":
			a.sources[source] = &binaryedge.Source{}
		case "bufferover":
			a.sources[source] = &bufferover.Source{}
		case "cebaidu":
			a.sources[source] = &cebaidu.Source{}
		case "censys":
			a.sources[source] = &censys.Source{}
		case "certspotter":
			a.sources[source] = &certspotter.Source{}
		case "certspotterold":
			a.sources[source] = &certspotterold.Source{}
		case "commoncrawl":
			a.sources[source] = &commoncrawl.Source{}
		case "crtsh":
			a.sources[source] = &crtsh.Source{}
		case "dnsdumpster":
			a.sources[source] = &dnsdumpster.Source{}
		case "dnsdb":
			a.sources[source] = &dnsdb.Source{}
		case "github":
			a.sources[source] = &github.Source{}
		case "hackertarget":
			a.sources[source] = &hackertarget.Source{}
		case "ipv4info":
			a.sources[source] = &ipv4info.Source{}
		case "intelx":
			a.sources[source] = &intelx.Source{}
		case "passivetotal":
			a.sources[source] = &passivetotal.Source{}
		case "rapiddns":
			a.sources[source] = &rapiddns.Source{}
		case "recon":
			a.sources[source] = &recon.Source{}
		case "riddler":
			a.sources[source] = &riddler.Source{}
		case "robtex":
			a.sources[source] = &robtex.Source{}
		case "securitytrails":
			a.sources[source] = &securitytrails.Source{}
		case "shodan":
			a.sources[source] = &shodan.Source{}
		case "sitedossier":
			a.sources[source] = &sitedossier.Source{}
		case "sonarsearch":
			a.sources[source] = &sonarsearch.Source{}
		case "spyse":
			a.sources[source] = &spyse.Source{}
		case "sublist3r":
			a.sources[source] = &sublist3r.Source{}
		case "threatbook":
			a.sources[source] = &threatbook.Source{}
		case "threatcrowd":
			a.sources[source] = &threatcrowd.Source{}
		case "threatminer":
			a.sources[source] = &threatminer.Source{}
		case "virustotal":
			a.sources[source] = &virustotal.Source{}
		case "waybackarchive":
			a.sources[source] = &waybackarchive.Source{}
		case "ximcx":
			a.sources[source] = &ximcx.Source{}
		case "zoomeye":
			a.sources[source] = &zoomeye.Source{}
		}
	}
}
