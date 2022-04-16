package password

import (
	"context"
	"github.com/travelata/auth/config"
	"github.com/travelata/auth/logger"
	"github.com/travelata/kit/log"

	"github.com/sethvargo/go-password/password"
)

type serviceImpl struct {
	config.Password
}

func (s *serviceImpl) l() log.CLogger {
	return logger.L().Cmp("password-gen")
}

func New() *serviceImpl {
	return &serviceImpl{}
}

func (s *serviceImpl) Init(cfg *config.Password) {
	s.Password = *cfg
}

func (s *serviceImpl) Generate(ctx context.Context) (string, error) {
	s.l().C(ctx).Mth("generate").Dbg()
	return password.Generate(int(s.Length), int(s.NumSymbols), int(s.NumDigits), s.AllowRepeat, s.NoUpper)
}
