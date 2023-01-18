package test

import (
	"context"
	"fmt"
	"github.com/Rewriterl/ifgather/internal/cmd"
	"github.com/Rewriterl/ifgather/internal/dao"
	"github.com/Rewriterl/ifgather/utility/ipquery"
	_ "github.com/gogf/gf/contrib/drivers/pgsql/v2"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/test/gtest"
	"regexp"
	"testing"
)

func TestUsersDaoModify(t *testing.T) {
	gtest.C(t, func(t *gtest.T) {
		//result, err := dao.Users.Ctx(context.Background()).Update("id = ?", "id = ?", 1, 2)

		result, err := g.Model("users").Data("id = ?", 1).Where("id = ?", 2).Update()
		if err != nil {
			return
		}
		gtest.AssertEQ(err, nil)
		s := fmt.Sprintf("%+v", result)
		fmt.Println(s)
	})
}

func TestUsersDao(t *testing.T) {
	gtest.C(t, func(t *gtest.T) {
		one, err := dao.Users.Ctx(context.Background()).One("username = ?", "test")
		gtest.AssertEQ(err, nil)
		s := fmt.Sprintf("%+v", one)
		fmt.Println(s)
	})
}

func TestReadConfig(t *testing.T) {
	gtest.C(t, func(t *gtest.T) {
		mustGet := g.Cfg().MustGet(context.Background(), "nsq.tcpHost")
		s := fmt.Sprintf("%+v", mustGet)
		fmt.Println(s)
		//gtest.AssertEQ(err, nil)
	})
}

func TestIpQuery(t *testing.T) {
	gtest.C(t, func(t *gtest.T) {
		info, err := ipquery.QueryIp("20.205.243.166")
		location := ipquery.QueryLocation(info)
		fmt.Println(location)
		gtest.AssertEQ(err, nil)
	})
}

func TestPasswd(t *testing.T) {
	gtest.C(t, func(t *gtest.T) {
		upper := regexp.MustCompile(`[A-Z]`)
		lower := regexp.MustCompile(`[a-z]`)
		number := regexp.MustCompile(`[0-9]`)
		special := regexp.MustCompile(`[!@#\$%\^&\*\(\)_\+\-=\{\}\[\]\\|;:'",.<>\/?]`)
		password := cmd.GeneratePassword(6, true, true, true, true)
		fmt.Println(password)
		gtest.AssertEQ(upper.MatchString(password) &&
			lower.MatchString(password) &&
			number.MatchString(password) &&
			special.MatchString(password), true)
	})
}
