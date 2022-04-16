package storage

import (
	"encoding/json"
	"github.com/travelata/auth/domain"
	kitDb "github.com/travelata/kit/db"
)

func (s *userStorageImpl) toUserDto(rq *domain.User) *user {
	if rq == nil {
		return nil
	}

	u := &user{
		Id:        rq.Id,
		Username:  rq.Username,
		Password:  kitDb.StringToNull(rq.Password),
		Type:      rq.Type,
		AuthType:  rq.AuthType,
		Status:    rq.Status,
		CreatedAt: rq.CreatedAt,
		UpdatedAt: rq.UpdatedAt,
		DeletedAt: rq.DeletedAt,
	}

	var detailsBytes []byte
	detailsBytes, _ = json.Marshal(u.Details)
	u.Details = string(detailsBytes)

	return u
}

func (s *userStorageImpl) toUserIndex(d *domain.User) *iUser {
	i := &iUser{
		Username: d.Username,
		Type:     d.Type,
		Status:   d.Status,
		Email:    d.Details.Email,
		Groups:   d.Details.Groups,
		Roles:    d.Details.Roles,
		Deleted:  d.DeletedAt != nil,
	}

	return i
}

func (s *userStorageImpl) toUserDomain(dto *user) *domain.User {
	if dto == nil {
		return nil
	}

	u := &domain.User{
		Id:        dto.Id,
		Username:  dto.Username,
		Type:      dto.Type,
		AuthType:  dto.AuthType,
		Status:    dto.Status,
		Password:  kitDb.NullToString(dto.Password),
		CreatedAt: dto.CreatedAt,
		UpdatedAt: dto.UpdatedAt,
	}

	cd := &domain.UserDetails{}
	_ = json.Unmarshal([]byte(dto.Details), cd)
	u.Details = cd

	return u
}

func (s *userStorageImpl) toUsersDomain(dto []*user) []*domain.User {
	var res []*domain.User

	for _, v := range dto {
		res = append(res, s.toUserDomain(v))
	}

	return res
}
