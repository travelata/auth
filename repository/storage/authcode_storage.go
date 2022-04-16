package storage

import (
	"context"
	"encoding/json"
	"github.com/go-redis/redis"
	"github.com/travelata/auth/domain"
	"github.com/travelata/auth/errors"
	"github.com/travelata/auth/logger"
	"github.com/travelata/kit"
	"github.com/travelata/kit/log"
)

const (
	CacheKeyUserAuthCode = "auth-code."
)

type authCodeStorageImpl struct {
	c *container
}

func (s *authCodeStorageImpl) l() log.CLogger {
	return logger.L().Cmp("auth-code-storage")
}

func newAuthCodeStorage(c *container) *authCodeStorageImpl {
	s := &authCodeStorageImpl{c}
	return s
}

func (s *authCodeStorageImpl) Set(ctx context.Context, code *domain.AuthCode) error {
	s.l().C(ctx).Mth("set").F(log.FF{"username": code.Username}).Dbg()

	key := CacheKeyUserAuthCode + code.Username

	b, err := json.Marshal(code)
	if err != nil {
		return errors.ErrAuthCodeStorageMarshal(err, ctx)
	}

	exp := code.ExpiresAt.Sub(kit.Now())
	if err = s.c.Cache.Instance.Set(key, b, exp).Err(); err != nil {
		return errors.ErrAuthCodeStorageSet(err, ctx)
	}

	return nil
}

func (s *authCodeStorageImpl) Get(ctx context.Context, username string) (bool, *domain.AuthCode, error) {

	s.l().C(ctx).Mth("set").F(log.FF{"username": username}).Dbg()

	key := CacheKeyUserAuthCode + username
	if j, err := s.c.Cache.Instance.Get(key).Result(); err == nil {
		authCode := &domain.AuthCode{}
		err := json.Unmarshal([]byte(j), &authCode)
		if err != nil {
			return true, nil, errors.ErrAuthCodeStorageUnMarshal(err, ctx)
		}
		return true, authCode, err
	} else {
		if err == redis.Nil {
			return false, nil, nil
		} else {
			return false, nil, errors.ErrAuthCodeStorageGet(err, ctx)
		}
	}

}
