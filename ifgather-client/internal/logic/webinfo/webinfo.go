package webinfo

import "github.com/Rewriterl/ifgather-client/internal/logic/webinfo/banalyze"

// ResultWebInfo web探测返回信息
type ResultWebInfo struct {
	Url           string                         `json:"url"`
	StatusCode    int                            `json:"status_code"`
	Title         string                         `json:"title"`
	ContentLength int                            `json:"content_length"`
	Banalyze      map[string]*banalyze.ResultApp `json:"banalyze"`
	SubDomaina    []string                       `json:"subdomaina"`
	Js            []string                       `json:"js"`
	Urls          []string                       `json:"urls"`
	Forms         []string                       `json:"forms"`
	Keys          []string                       `json:"keys"`
}

// Detection web探测所需信息
type Detection struct {
	SubDomain   []string
	ServiceName string
	Port        int
}
