package ipquery

import (
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"regexp"
)

// QueryIp 查询IP位置信息
func QueryIp(ip string) (string, error) {
	cBuff, err := xdb.LoadContentFromFile("utility/ipquery/ip2region.xdb")
	if err != nil {
		return "", err
	}
	searcher, err := xdb.NewWithBuffer(cBuff)
	region, err := searcher.SearchByStr(ip)
	if err != nil {
		return "", err
	}
	return region, nil
}

func QueryLocation(str string) string {
	re := regexp.MustCompile(`^([^|]+)`)
	match := re.FindString(str)
	return match
}
