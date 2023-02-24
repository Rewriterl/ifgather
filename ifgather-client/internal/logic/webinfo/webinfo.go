package webinfo

import (
	"crypto/tls"
	"fmt"
	"github.com/Rewriterl/ifgather-client/internal/logic/webinfo/banalyze"
	"github.com/axgle/mahonia"
	"github.com/gogf/gf/v2/encoding/ghtml"
	"github.com/gogf/gf/v2/text/gregex"
	"github.com/parnurzeal/gorequest"
	"github.com/saintfish/chardet"
	"strings"
	"time"
)

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

type HttpInfo struct {
	SubDomain     string
	ServiceName   string
	Port          int
	Url           string
	StatusCode    int
	Title         string
	ContentLength int
	Timeout       int
}

// 发送HTTP数据包
func (h *HttpInfo) SendHttp() {
	if strings.Contains(h.ServiceName, "http") && !strings.Contains(h.ServiceName, "https") {
		h.Url = fmt.Sprintf("https://%s:%d", h.SubDomain, h.Port)
		err := h.SendHttp1()
		if err != nil {
			h.Url = fmt.Sprintf("http://%s:%d", h.SubDomain, h.Port)
			h.SendHttp1()
		}
	} else {
		h.Url = fmt.Sprintf("https://%s:%d", h.SubDomain, h.Port)
		h.SendHttp1()
	}
}

// 发送HTTP数据包
func (h *HttpInfo) SendHttp1() error {
	resp, body, err := gorequest.New().
		Get(h.Url).
		Timeout(time.Duration(int64(h.Timeout))*time.Second).
		TLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		AppendHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9").
		AppendHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 11) AppleWebKit/538.41 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36").
		End()
	if err != nil {
		return err[0]
	}
	h.StatusCode = resp.StatusCode
	h.ContentLength = len(body)
	h.getTitle(body)
	return nil
}

// 获取网页标题
func (h *HttpInfo) getTitle(s string) {
	list, err := gregex.MatchString("<title>(.*?)</title>", s)
	if err != nil {
		return
	}
	if len(list) == 0 {
		return
	}
	title := list[len(list)-1]
	detector := chardet.NewTextDetector()
	char, err := detector.DetectBest([]byte(title)) // 检测编码类型
	if err != nil {
		return
	}
	if char.Charset == "UTF-8" {
		h.Title = ghtml.SpecialChars(title)
		return
	}
	h.Title = h.ConvertToString(ghtml.SpecialChars(title), "GBK", "utf-8")
	return
}

// 编码转换成utf-8编码
func (h *HttpInfo) ConvertToString(src string, srcCode string, tagCode string) string {
	srcCoder := mahonia.NewDecoder(srcCode)
	srcResult := srcCoder.ConvertString(src)
	tagCoder := mahonia.NewDecoder(tagCode)
	_, cdata, _ := tagCoder.Translate([]byte(srcResult), true)
	result := string(cdata)
	return result
}
