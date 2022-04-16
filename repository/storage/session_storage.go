package storage

import (
	"context"
	"encoding/json"
	"github.com/go-redis/redis"
	"github.com/travelata/auth/domain"
	"github.com/travelata/auth/errors"
	"github.com/travelata/auth/logger"
	"github.com/travelata/kit/log"
	"time"
)

const (
	CacheKeySessionSid = "session."
)

type sessionStorageImpl struct {
	c *container
}

type session struct {
	Id             string     `gorm:"column:id"`
	UserId         string     `gorm:"column:user_id"`
	Username       string     `gorm:"column:username"`
	LoginAt        time.Time  `gorm:"column:login_at"`
	LastActivityAt time.Time  `gorm:"column:last_activity_at"`
	LogoutAt       *time.Time `gorm:"column:logout_at"`
	Details        string     `gorm:"column:details"`
}

func newSessionStorage(c *container) *sessionStorageImpl {
	return &sessionStorageImpl{c: c}
}

func (s *sessionStorageImpl) l() log.CLogger {
	return logger.L().Cmp("session-storage")
}

func (s *sessionStorageImpl) setSessionCache(ctx context.Context, ss *domain.Session) error {

	l := s.l().Mth("session-cache").C(ctx).Dbg()

	key := CacheKeySessionSid + ss.Id

	js, err := json.Marshal(ss)
	if err != nil {
		l.E(err).St().Err()
	}

	// set cache for id key
	if err = s.c.Cache.Instance.Set(key, string(js), time.Minute*30).Err(); err != nil {
		return errors.ErrSessionStorageSessionCache(err, ctx)
	}

	return nil

}

func (s *sessionStorageImpl) Get(ctx context.Context, sid string) (bool, *domain.Session, error) {
	l := s.l().C(ctx).Mth("get").F(log.FF{"sid": sid}).Dbg()

	if sid == "" {
		return false, nil, errors.ErrSessionStorageGetDbEmptySid(ctx)
	}

	key := CacheKeySessionSid + sid
	if j, err := s.c.Cache.Instance.Get(key).Result(); err == nil {
		session := &domain.Session{}
		err = json.Unmarshal([]byte(j), &session)
		return true, session, err
	} else {
		if err == redis.Nil {
			dto := &session{Id: sid}
			if res := s.c.Db.Instance.Limit(1).Find(&dto); res.Error == nil {
				l.DbgF("db: found %d", res.RowsAffected)
				if res.RowsAffected == 0 {
					return false, nil, nil
				} else {
					session := s.toSessionDomain(dto)
					// set cache
					if err := s.setSessionCache(ctx, session); err != nil {
						return true, nil, err
					}
					return true, session, nil
				}
			} else {
				return false, nil, errors.ErrSessionStorageGetDb(err, ctx)
			}
		} else {
			return false, nil, errors.ErrSessionStorageGetCache(err, ctx)
		}
	}
}

func (s *sessionStorageImpl) GetByUser(ctx context.Context, uid string) ([]*domain.Session, error) {
	s.l().C(ctx).Mth("get-by-user").F(log.FF{"uid": uid}).Dbg()

	var sessions []*session
	if err := s.c.Db.Instance.Where("user_id = ?::uuid and logout_at is null", uid).Find(&sessions).Error; err == nil {
		return s.toSessionsDomain(sessions), nil
	} else {
		return nil, errors.ErrSessionGetByUser(err, ctx)
	}
}

func (s *sessionStorageImpl) CreateSession(ctx context.Context, session *domain.Session, token *domain.SessionToken) error {
	l := s.l().C(ctx).Mth("create-session").F(log.FF{"sid": session.Id}).Dbg()

	// session
	sessDto := s.toSessionDto(session)
	if err := s.c.Db.Instance.Create(sessDto).Error; err != nil {
		return errors.ErrSessionStorageCreateSession(err, ctx)
	}
	l.Dbg("session created")

	// set cache
	if err := s.setSessionCache(ctx, session); err != nil {
		return err
	}

	return nil
}

func (s *sessionStorageImpl) UpdateLastActivity(ctx context.Context, sid string, lastActivity time.Time) error {
	s.l().Mth("logout").C(ctx).F(log.FF{"sid": sid}).Dbg()

	// update DB
	if err := s.c.Db.Instance.Model(&session{Id: sid}).
		Updates(map[string]interface{}{
			"last_activity_at": lastActivity,
		}).Error; err != nil {
		return errors.ErrSessionStorageUpdateLastActivity(err, ctx)
	}
	return nil
}

func (s *sessionStorageImpl) Logout(ctx context.Context, sid string, logoutAt time.Time) error {
	s.l().Mth("logout").C(ctx).F(log.FF{"sid": sid}).Dbg()

	// update DB
	if err := s.c.Db.Instance.Model(&session{Id: sid}).
		Updates(map[string]interface{}{
			"logout_at": logoutAt,
		}).Error; err != nil {
		return errors.ErrSessionStorageUpdateLogout(err, ctx)
	}

	// clear cache
	s.c.Cache.Instance.Del(CacheKeySessionSid + sid)

	return nil
}
