// =================================================================================
// Code generated by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package entity

import (
	"github.com/gogf/gf/v2/os/gtime"
)

// ScanWeb is the golang structure for table scan_web.
type ScanWeb struct {
	Id             int         `json:"id"             ` //
	CusName        string      `json:"cusName"        ` //
	Url            string      `json:"url"            ` //
	Code           int         `json:"code"           ` //
	Title          string      `json:"title"          ` //
	ContentLength  int         `json:"contentLength"  ` //
	Fingerprint    string      `json:"fingerprint"    ` //
	Image          string      `json:"image"          ` //
	ScreenshotFlag bool        `json:"screenshotFlag" ` //
	Js             string      `json:"js"             ` //
	Urls           string      `json:"urls"           ` //
	Forms          string      `json:"forms"          ` //
	Secret         string      `json:"secret"         ` //
	Flag           bool        `json:"flag"           ` //
	NsqFlag        bool        `json:"nsqFlag"        ` //
	ScanFlag       bool        `json:"scanFlag"       ` //
	ScanNsqFlag    bool        `json:"scanNsqFlag"    ` //
	CreateAt       *gtime.Time `json:"createAt"       ` //
}
