// ==========================================================================
// This is auto-generated by gf cli tool. DO NOT EDIT THIS FILE MANUALLY.
// ==========================================================================

package internal

import "github.com/gogf/gf/v2/os/gtime"

// UserIp is the golang structure for table user_ip.
type UserIp struct {
	Id       int         `orm:"id"        json:"id"`        //
	Ip       string      `orm:"ip"        json:"ip"`        //
	Lock     int         `orm:"lock"      json:"lock"`      //
	CreateAt *gtime.Time `orm:"create_at" json:"create_at"` //
}