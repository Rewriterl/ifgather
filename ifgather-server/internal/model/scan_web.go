// ==========================================================================
// This is auto-generated by gf cli tool. Fill this file as you wish.
// ==========================================================================

package model

import (
	"github.com/Rewriterl/ifgather-server/internal/model/internal"
)

// ScanWeb is the golang structure for table scan_web.
type ScanWeb internal.ScanWeb

// Fill with you ideas below.

// 返回指定url的爬虫结果
type ScanWebTreeReq struct {
	Url string `v:"required#参数不能为空"`
}

// web爬虫返回结果
type ReScanWebTree struct {
	Code      int                 `json:"code"`
	Msg       string              `json:"msg"`
	UrlData   []ReScanWebTreeInfo `json:"urldata"`
	JsData    []ReScanWebTreeInfo `json:"jsdata"`
	FormsData []ReScanWebTreeInfo `json:"formsdata"`
	Secret    string              `json:"secret"`
	Images    string              `json:"images"`
}

// web爬虫详细结果
type ReScanWebTreeInfo struct {
	Title string `json:"title"`
	Href  string `json:"href"`
}
