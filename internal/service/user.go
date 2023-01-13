package service

import "context"

type serviceUser struct{}

var User = new(serviceUser)

func (s *serviceUser) Login(ctx context.Context) {

}
