package storage

import (
	"github.com/travelata/auth/domain"
	kitStorage "github.com/travelata/kit/db"
)

func (s *securityStorageImpl) toGroupDto(d *domain.Group) *group {
	return &group{
		CreatedAt:    d.CreatedAt,
		UpdatedAt:    d.UpdatedAt,
		Code:         d.Code,
		Name:         d.Name,
		Description:  kitStorage.StringToNull(d.Description),
		UserType:     d.UserType,
		DefaultGroup: d.Default,
		Internal:     d.Internal,
	}
}

func (s *securityStorageImpl) toGroupDomain(d *group) *domain.Group {
	return &domain.Group{
		Code:        d.Code,
		Name:        d.Name,
		Description: kitStorage.NullToString(d.Description),
		UserType:    d.UserType,
		Default:     d.DefaultGroup,
		Internal:    d.Internal,
		CreatedAt:   d.CreatedAt,
		UpdatedAt:   d.UpdatedAt,
	}
}

func (s *securityStorageImpl) toGroupsDomain(d []*group) []*domain.Group {
	var r []*domain.Group
	for _, gr := range d {
		r = append(r, s.toGroupDomain(gr))
	}
	return r
}

func (s *securityStorageImpl) toRoleDto(d *domain.Role) *role {
	r := &role{
		Code:        d.Code,
		Name:        d.Name,
		Description: kitStorage.StringToNull(d.Description),
		Internal:    d.Internal,
		CreatedAt:   d.CreatedAt,
		UpdatedAt:   d.UpdatedAt,
	}
	return r
}

func (s *securityStorageImpl) toRoleDomain(d *role) *domain.Role {
	r := &domain.Role{
		Code:        d.Code,
		Name:        d.Name,
		Description: kitStorage.NullToString(d.Description),
		Internal:    d.Internal,
		CreatedAt:   d.CreatedAt,
		UpdatedAt:   d.UpdatedAt,
	}
	return r
}

func (s *securityStorageImpl) toRolesDomain(d []*role) []*domain.Role {
	var r []*domain.Role
	for _, rl := range d {
		r = append(r, s.toRoleDomain(rl))
	}
	return r
}

func (s *securityStorageImpl) toResourceDto(d *domain.Resource) *resource {
	return &resource{
		CreatedAt:   d.CreatedAt,
		UpdatedAt:   d.UpdatedAt,
		Code:        d.Code,
		Name:        d.Name,
		Description: kitStorage.StringToNull(d.Description),
		Internal:    d.Internal,
	}
}

func (s *securityStorageImpl) toResourceDomain(d *resource) *domain.Resource {
	return &domain.Resource{
		Code:        d.Code,
		Name:        d.Name,
		Description: kitStorage.NullToString(d.Description),
		Internal:    d.Internal,
		CreatedAt:   d.CreatedAt,
		UpdatedAt:   d.UpdatedAt,
	}
}

func (s *securityStorageImpl) toResourcesDomain(d []*resource) []*domain.Resource {
	var r []*domain.Resource
	for _, rs := range d {
		r = append(r, s.toResourceDomain(rs))
	}
	return r
}

func (s *securityStorageImpl) toPermissionDto(resource, role string, p *domain.Permissions) *permission {
	return &permission{
		ResourceCode: resource,
		RoleCode:     role,
		AllowR:       p.Allow.R,
		AllowW:       p.Allow.W,
		AllowX:       p.Allow.X,
		AllowD:       p.Allow.D,
		DenyR:        p.Deny.R,
		DenyW:        p.Deny.W,
		DenyX:        p.Deny.X,
		DenyD:        p.Deny.D,
	}
}

func (s *securityStorageImpl) toPermissionDomain(dto *permission) *domain.Permissions {
	if dto == nil {
		return nil
	}
	return &domain.Permissions{
		Allow: domain.RWXD{
			R: dto.AllowR,
			W: dto.AllowW,
			X: dto.AllowX,
			D: dto.AllowD,
		},
		Deny: domain.RWXD{
			R: dto.DenyR,
			W: dto.DenyW,
			X: dto.DenyX,
			D: dto.DenyD,
		},
	}
}

func (s *securityStorageImpl) toPermissionsDomain(d []*permission) []*domain.Permissions {
	var r []*domain.Permissions
	for _, p := range d {
		r = append(r, s.toPermissionDomain(p))
	}
	return r
}

func (s *securityStorageImpl) toWcPermissionDto(resourcePattern, role string, p *domain.Permissions) *wildcardPermission {
	return &wildcardPermission{
		ResourcePattern: resourcePattern,
		RoleCode:        role,
		AllowR:          p.Allow.R,
		AllowW:          p.Allow.W,
		AllowX:          p.Allow.X,
		AllowD:          p.Allow.D,
		DenyR:           p.Deny.R,
		DenyW:           p.Deny.W,
		DenyX:           p.Deny.X,
		DenyD:           p.Deny.D,
	}
}

func (s *securityStorageImpl) toWcPermissionDomain(dto *wildcardPermission) *domain.Permissions {
	if dto == nil {
		return nil
	}
	return &domain.Permissions{
		Allow: domain.RWXD{
			R: dto.AllowR,
			W: dto.AllowW,
			X: dto.AllowX,
			D: dto.AllowD,
		},
		Deny: domain.RWXD{
			R: dto.DenyR,
			W: dto.DenyW,
			X: dto.DenyX,
			D: dto.DenyD,
		},
	}
}

func (s *securityStorageImpl) toWcPermissionsDomain(d []*wildcardPermission) []*domain.Permissions {
	var r []*domain.Permissions
	for _, p := range d {
		r = append(r, s.toWcPermissionDomain(p))
	}
	return r
}

func (s *securityStorageImpl) toRoleResourcePermissionsDomain(d []*permission) []*domain.RoleResourcePermission {
	var r []*domain.RoleResourcePermission
	for _, p := range d {
		r = append(r, &domain.RoleResourcePermission{
			RoleCode:     p.RoleCode,
			ResourceCode: p.ResourceCode,
			Permissions:  s.toPermissionDomain(p),
		})
	}
	return r
}

func (s *securityStorageImpl) toRoleWcPermissionsDomain(d []*wildcardPermission) []*domain.RoleWildCardPermission {
	var r []*domain.RoleWildCardPermission
	for _, p := range d {
		r = append(r, &domain.RoleWildCardPermission{
			RoleCode:        p.RoleCode,
			ResourcePattern: p.ResourcePattern,
			Permissions:     s.toWcPermissionDomain(p),
		})
	}
	return r
}
