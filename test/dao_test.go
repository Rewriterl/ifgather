package test

import (
	"context"
	"fmt"
	"github.com/Rewriterl/ifgather/internal/dao"
	_ "github.com/Rewriterl/ifgather/utility/pqsql"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/test/gtest"
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
		one, err := dao.Users.Ctx(context.Background()).One("username = ?", "admin")
		gtest.AssertEQ(err, nil)
		s := fmt.Sprintf("%+v", one)
		fmt.Println(s)
	})
}
