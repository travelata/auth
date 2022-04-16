package storage

import (
	"context"
	"encoding/json"
	"github.com/go-redis/redis"
	"github.com/google/uuid"
	"github.com/olivere/elastic/v7"
	"github.com/travelata/auth/domain"
	"github.com/travelata/auth/errors"
	"github.com/travelata/auth/logger"
	"github.com/travelata/kit/common"
	"github.com/travelata/kit/log"
	"math"
	"time"
)

const (
	CacheKeyUserId   = "user-id."
	CacheKeyUsername = "user-un."
	IndexUsers       = "users"
)

type user struct {
	Id        string     `gorm:"column:id;primaryKey"`
	Username  string     `gorm:"column:username"`
	Password  *string    `gorm:"column:password"`
	Type      string     `gorm:"column:type"`
	AuthType  string     `gorm:"column:auth_type"`
	Status    string     `gorm:"column:status"`
	Details   string     `gorm:"column:details"`
	CreatedAt time.Time  `gorm:"column:created_at"`
	UpdatedAt time.Time  `gorm:"column:updated_at"`
	DeletedAt *time.Time `gorm:"column:deleted_at"`
}

type iUser struct {
	Username string   `json:"username" es:"type:keyword"`
	Type     string   `json:"type" es:"type:keyword"`
	Status   string   `json:"status" es:"type:keyword"`
	Email    string   `json:"email" es:"type:keyword"`
	Groups   []string `json:"groups" es:"type:keyword"`
	Roles    []string `json:"roles" es:"type:keyword"`
	Deleted  bool     `json:"deleted" es:"type:boolean"`
}

type userStorageImpl struct {
	c *container
}

func newUserStorage(c *container) *userStorageImpl {
	s := &userStorageImpl{c}
	return s
}

func (s *userStorageImpl) l() log.CLogger {
	return logger.L().Cmp("users-storage")
}

func (s *userStorageImpl) setCacheAsync(ctx context.Context, dto user) {

	go func() {

		l := s.l().Mth("set-cache").C(ctx).Dbg()

		keyUserId := CacheKeyUserId + dto.Id
		keyUsername := CacheKeyUsername + dto.Username

		j, err := json.Marshal(dto)
		if err != nil {
			l.E(err).St().Err()
		}

		// set cache for id key
		if err := s.c.Cache.Instance.Set(keyUserId, string(j), time.Hour).Err(); err != nil {
			l.E(errors.ErrUserStorageSetCache(err, ctx)).St().Err()
		}

		// set cache for username key
		if err := s.c.Cache.Instance.Set(keyUsername, string(j), time.Hour).Err(); err != nil {
			l.E(errors.ErrUserStorageSetCache(err, ctx)).St().Err()
		}

	}()
}

func (s *userStorageImpl) ensureIndex() error {
	return s.c.Search.BuildIndexWithModel(IndexUsers, &iUser{})
}

func (s *userStorageImpl) Create(ctx context.Context, user *domain.User) error {
	s.l().Mth("create").C(ctx).F(log.FF{"id": user.Id}).Dbg()

	dto := s.toUserDto(user)
	result := s.c.Db.Instance.Create(dto)
	if result.Error != nil {
		return errors.ErrUserStorageCreate(result.Error, ctx)
	}
	s.c.Search.IndexAsync(IndexUsers, dto.Id, s.toUserIndex(user))

	return nil
}

func (s *userStorageImpl) Update(ctx context.Context, user *domain.User) error {
	s.l().Mth("update").C(ctx).F(log.FF{"id": user.Id})

	dto := s.toUserDto(user)

	if err := s.c.Db.Instance.Save(dto).Error; err != nil {
		return errors.ErrUserStorageUpdate(err, ctx)
	}

	// clear cache
	keys := []string{CacheKeyUsername + user.Username, CacheKeyUserId + user.Id}
	s.c.Cache.Instance.Del(keys...)

	// async indexing
	s.c.Search.IndexAsync(IndexUsers, dto.Id, s.toUserIndex(user))

	return nil
}

func (s *userStorageImpl) GetByUsername(ctx context.Context, un string) (bool, *domain.User, error) {
	l := s.l().Mth("get-username").C(ctx).F(log.FF{"username": un}).Dbg()

	keyUserName := CacheKeyUsername + un
	if j, err := s.c.Cache.Instance.Get(keyUserName).Result(); err == nil {
		// found in cache

		l.Dbg("found in cache")

		dto := &user{}
		if err := json.Unmarshal([]byte(j), &dto); err != nil {
			return true, nil, err
		}

		return true, s.toUserDomain(dto), nil

	} else {

		if err == redis.Nil {
			// not found in cache

			l.Dbg("not found in cache")

			dto := &user{}
			if res := s.c.Db.Instance.
				Where("username = ? and deleted_at is null", un).
				Limit(1).
				Find(&dto); res.Error == nil {

				l.DbgF("db: found %d", res.RowsAffected)

				if res.RowsAffected == 0 {
					return false, nil, nil
				} else {
					// set cache async
					s.setCacheAsync(ctx, *dto)

					return true, s.toUserDomain(dto), nil
				}

			} else {
				return false, nil, errors.ErrUserStorageGetDb(res.Error, ctx)
			}

		} else {
			return false, nil, errors.ErrUserStorageGetCache(err, ctx)
		}
	}
}

func (s *userStorageImpl) Get(ctx context.Context, id string) (bool, *domain.User, error) {
	l := s.l().Mth("get").C(ctx).F(log.FF{"id": id}).Dbg()

	// check if GUID passed
	// if not, consider it to be a username
	_, err := uuid.Parse(id)
	if err != nil {
		l.Dbg("username identified")
		return s.GetByUsername(ctx, id)
	}

	keyUserId := CacheKeyUserId + id
	if j, err := s.c.Cache.Instance.Get(keyUserId).Result(); err == nil {
		// found in cache

		l.Dbg("found in cache")

		dto := &user{}
		if err := json.Unmarshal([]byte(j), &dto); err != nil {
			return true, nil, err
		}
		return true, s.toUserDomain(dto), nil

	} else {

		if err == redis.Nil {
			// not found in cache
			dto := &user{Id: id}
			if res := s.c.Db.Instance.Limit(1).Find(&dto, "deleted_at is null"); res.Error == nil {
				l.DbgF("db: found %d", res.RowsAffected)
				if res.RowsAffected == 0 {
					return false, nil, nil
				} else {
					// set cache async
					s.setCacheAsync(ctx, *dto)
					return true, s.toUserDomain(dto), nil
				}
			} else {
				return false, nil, errors.ErrUserStorageGetDb(res.Error, ctx)
			}

		} else {
			return false, nil, errors.ErrUserStorageGetCache(err, ctx)
		}
	}
}

func (s *userStorageImpl) GetByIds(ctx context.Context, ids []string) ([]*domain.User, error) {
	s.l().Mth("get-ids").C(ctx).Dbg()
	var users []*user
	if err := s.c.Db.Instance.Find(&users, ids).Error; err != nil {
		return nil, errors.ErrUserStorageGetByIds(err, ctx)
	}
	return s.toUsersDomain(users), nil
}

func (s *userStorageImpl) Search(ctx context.Context, cr *domain.UserSearchCriteria) (*domain.UserSearchResponse, error) {
	l := s.l().Mth("search").C(ctx).Dbg().TrcObj("%v", cr)

	response := &domain.UserSearchResponse{
		PagingResponse: &common.PagingResponse{},
		Users:          []*domain.User{},
	}

	cl := s.c.Search.GetClient()

	bq := elastic.NewBoolQuery()
	bq = bq.Must(elastic.NewMatchAllQuery())

	var queries []elastic.Query

	if cr.Username != "" {
		queries = append(queries, elastic.NewTermQuery("username", cr.Username))
	}

	if cr.Email != "" {
		queries = append(queries, elastic.NewTermQuery("email", cr.Email))
	}

	if cr.Status != "" {
		queries = append(queries, elastic.NewTermQuery("status", cr.Status))
	}

	if cr.UserGroup != "" {
		queries = append(queries, elastic.NewTermQuery("groups", cr.UserGroup))
	}

	if cr.UserRole != "" {
		queries = append(queries, elastic.NewTermQuery("roles", cr.UserRole))
	}

	if cr.UserType != "" {
		queries = append(queries, elastic.NewTermQuery("type", cr.UserType))
	}

	queries = append(queries, elastic.NewTermQuery("deleted", "false"))

	// paging
	from := (cr.Index - 1) * cr.Size
	if from < 0 {
		from = 0
	}

	bq = bq.Filter(queries...)
	sr, err := cl.Search(IndexUsers).
		Query(bq).
		From(from).
		Size(cr.Size).
		Do(ctx)
	if err != nil {
		return nil, errors.ErrUserSearch(err, ctx)
	}

	var ids []string

	if sr.TotalHits() > 0 {
		for _, sh := range sr.Hits.Hits {
			ids = append(ids, sh.Id)
		}
	}

	response.PagingResponse.Total = int(math.Ceil(float64(sr.TotalHits()) / float64(cr.Size)))
	response.PagingResponse.Index = cr.Index

	if len(ids) > 0 {
		response.Users, err = s.GetByIds(ctx, ids)
		if err != nil {
			return nil, err
		}
	}

	l.TrcF("index: %d, db: %d", len(ids), len(response.Users))

	return response, nil
}
