package storage

import (
	"encoding/json"
	"github.com/travelata/auth/domain"
)

func (s *sessionStorageImpl) toSessionDto(d *domain.Session) *session {
	if d == nil {
		return nil
	}

	dto := &session{
		Id:             d.Id,
		UserId:         d.UserId,
		Username:       d.Username,
		LoginAt:        d.LoginAt,
		LastActivityAt: d.LastActivityAt,
		LogoutAt:       d.LogoutAt,
	}

	var detailsBytes []byte
	detailsBytes, _ = json.Marshal(d.Details)
	dto.Details = string(detailsBytes)

	return dto
}

func (s *sessionStorageImpl) toSessionDomain(dto *session) *domain.Session {

	if dto == nil {
		return nil
	}

	d := &domain.Session{
		Id:             dto.Id,
		UserId:         dto.UserId,
		Username:       dto.Username,
		LoginAt:        dto.LoginAt,
		LastActivityAt: dto.LastActivityAt,
		LogoutAt:       dto.LogoutAt,
	}

	cd := &domain.SessionDetails{}
	_ = json.Unmarshal([]byte(dto.Details), cd)
	d.Details = cd

	return d

}

func (s *sessionStorageImpl) toSessionsDomain(dtos []*session) []*domain.Session {
	var res []*domain.Session
	for _, d := range dtos {
		res = append(res, s.toSessionDomain(d))
	}
	return res
}
