package storage

import (
	"context"
	goErrors "errors"
	"github.com/travelata/auth/domain"
	"github.com/travelata/auth/errors"
	"github.com/travelata/auth/logger"
	"github.com/travelata/kit/log"
	"gorm.io/gorm"
	"time"
)

type securityStorageImpl struct {
	c *container
}

type group struct {
	Code         string  `gorm:"column:code;primaryKey"`
	Name         string  `gorm:"column:name"`
	Description  *string `gorm:"column:description"`
	UserType     string  `gorm:"column:user_type"`
	DefaultGroup bool    `gorm:"column:default_group"`
	Internal     bool    `gorm:"column:internal"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt
}

type role struct {
	Code        string  `gorm:"column:code;primaryKey"`
	Name        string  `gorm:"column:name"`
	Description *string `gorm:"column:description"`
	Internal    bool    `gorm:"column:internal"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt
}

type groupRole struct {
	GroupCode string `gorm:"column:group_code"`
	RoleCode  string `gorm:"column:role_code"`
	CreatedAt time.Time
	DeletedAt gorm.DeletedAt
}

type resource struct {
	Code        string  `gorm:"column:code;primaryKey"`
	Name        string  `gorm:"column:name"`
	Description *string `gorm:"column:description"`
	Internal    bool    `gorm:"column:internal"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt
}

type permission struct {
	ResourceCode string `gorm:"column:resource_code"`
	RoleCode     string `gorm:"column:role_code"`
	AllowR       bool   `gorm:"column:allow_r"`
	AllowW       bool   `gorm:"column:allow_w"`
	AllowX       bool   `gorm:"column:allow_x"`
	AllowD       bool   `gorm:"column:allow_d"`
	DenyR        bool   `gorm:"column:deny_r"`
	DenyW        bool   `gorm:"column:deny_w"`
	DenyX        bool   `gorm:"column:deny_x"`
	DenyD        bool   `gorm:"column:deny_d"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt
}

type wildcardPermission struct {
	ResourcePattern string `gorm:"column:resource_pattern"`
	RoleCode        string `gorm:"column:role_code"`
	AllowR          bool   `gorm:"column:allow_r"`
	AllowW          bool   `gorm:"column:allow_w"`
	AllowX          bool   `gorm:"column:allow_x"`
	AllowD          bool   `gorm:"column:allow_d"`
	DenyR           bool   `gorm:"column:deny_r"`
	DenyW           bool   `gorm:"column:deny_w"`
	DenyX           bool   `gorm:"column:deny_x"`
	DenyD           bool   `gorm:"column:deny_d"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DeletedAt       gorm.DeletedAt
}

func newSecurityStorage(c *container) *securityStorageImpl {
	return &securityStorageImpl{c: c}
}

func (s *securityStorageImpl) l() log.CLogger {
	return logger.L().Cmp("security-storage")
}

func (s *securityStorageImpl) CreateGroup(ctx context.Context, group *domain.Group) error {
	s.l().Mth("create-group").C(ctx).F(log.FF{"grp": group.Code}).Dbg()
	dto := s.toGroupDto(group)
	result := s.c.Db.Instance.Create(dto)
	if result.Error != nil {
		return errors.ErrSecurityStorageGroupCreate(result.Error, ctx)
	}
	return nil
}
func (s *securityStorageImpl) UpdateGroup(ctx context.Context, group *domain.Group) error {
	s.l().Mth("update-group").C(ctx).F(log.FF{"grp": group.Code}).Dbg()
	dto := s.toGroupDto(group)
	result := s.c.Db.Instance.Save(dto)
	if result.Error != nil {
		return errors.ErrSecurityStorageGroupUpdate(result.Error, ctx)
	}
	return nil
}

func (s *securityStorageImpl) DeleteGroup(ctx context.Context, code string) error {
	s.l().Mth("delete-group").C(ctx).F(log.FF{"grp": code}).Dbg()
	result := s.c.Db.Instance.Delete(&group{Code: code})
	if result.Error != nil {
		return errors.ErrSecurityStorageGroupDelete(result.Error, ctx)
	}
	return nil
}

func (s *securityStorageImpl) GetGroup(ctx context.Context, code string) (bool, *domain.Group, error) {
	s.l().Mth("get-group").C(ctx).F(log.FF{"grp": code}).Dbg()
	dto := &group{Code: code}
	if res := s.c.Db.Instance.Limit(1).Find(&dto); res.Error == nil {
		if res.RowsAffected == 0 {
			return false, nil, nil
		} else {
			return true, s.toGroupDomain(dto), nil
		}
	} else {
		return false, nil, errors.ErrSecurityStorageGroupGet(res.Error, ctx)
	}
}

func (s *securityStorageImpl) GetGroups(ctx context.Context) ([]*domain.Group, error) {
	s.l().Mth("get-groups").C(ctx).Dbg()
	var dtos []*group
	if res := s.c.Db.Instance.Find(&dtos); res.Error == nil {
		return s.toGroupsDomain(dtos), nil
	} else {
		return nil, errors.ErrSecurityStorageGroupsGet(res.Error, ctx)
	}
}

func (s *securityStorageImpl) UsersWithGroupExists(ctx context.Context, code string) (bool, error) {
	return false, nil
}

func (s *securityStorageImpl) CreateRole(ctx context.Context, role *domain.Role) error {
	s.l().Mth("create-role").C(ctx).F(log.FF{"grp": role.Code}).Dbg()
	dto := s.toRoleDto(role)
	result := s.c.Db.Instance.Create(dto)
	if result.Error != nil {
		return errors.ErrSecurityStorageRoleCreate(result.Error, ctx)
	}
	return nil
}

func (s *securityStorageImpl) UpdateRole(ctx context.Context, role *domain.Role) error {
	s.l().Mth("update-role").C(ctx).F(log.FF{"role": role.Code}).Dbg()
	dto := s.toRoleDto(role)
	result := s.c.Db.Instance.Save(dto)
	if result.Error != nil {
		return errors.ErrSecurityStorageRoleUpdate(result.Error, ctx)
	}
	return nil
}

func (s *securityStorageImpl) DeleteRole(ctx context.Context, code string) error {
	s.l().Mth("delete-role").C(ctx).F(log.FF{"role": code}).Dbg()
	result := s.c.Db.Instance.Delete(&role{Code: code})
	if result.Error != nil {
		return errors.ErrSecurityStorageRoleDelete(result.Error, ctx)
	}
	return nil
}

func (s *securityStorageImpl) GetRole(ctx context.Context, code string) (bool, *domain.Role, error) {
	s.l().Mth("get-role").C(ctx).F(log.FF{"role": code}).Dbg()
	dto := &role{Code: code}
	if res := s.c.Db.Instance.Limit(1).Find(&dto); res.Error == nil {
		if res.RowsAffected == 0 {
			return false, nil, nil
		} else {
			return true, s.toRoleDomain(dto), nil
		}
	} else {
		return false, nil, errors.ErrSecurityStorageRoleGet(res.Error, ctx)
	}
}

func (s *securityStorageImpl) GetAllRoles(ctx context.Context) ([]*domain.Role, error) {
	s.l().Mth("get-roles").C(ctx).Dbg()
	var dtos []*role
	if res := s.c.Db.Instance.Find(&dtos); res.Error == nil {
		return s.toRolesDomain(dtos), nil
	} else {
		return nil, errors.ErrSecurityStorageRolesGet(res.Error, ctx)
	}
}

func (s *securityStorageImpl) GetAllRoleCodes(ctx context.Context) ([]string, error) {
	s.l().Mth("get-roles").C(ctx).Dbg()
	var dtos []*role
	var codes []string
	if res := s.c.Db.Instance.Model(&dtos).Pluck("code", &codes); res.Error == nil {
		return codes, nil
	} else {
		return nil, errors.ErrSecurityStorageRoleCodesGet(res.Error, ctx)
	}
}

func (s *securityStorageImpl) UsersWithRoleExists(ctx context.Context, code string) (bool, error) {
	return false, nil
}

func (s *securityStorageImpl) CreateGroupRoles(ctx context.Context, groupCode string, roles []string) error {
	s.l().Mth("create-group-roles").C(ctx).F(log.FF{"grp": groupCode}).Dbg()
	var dtos []*groupRole
	for _, r := range roles {
		dtos = append(dtos, &groupRole{
			GroupCode: groupCode,
			RoleCode:  r,
		})
	}
	result := s.c.Db.Instance.Create(dtos)
	if result.Error != nil {
		return errors.ErrSecurityStorageGroupRoleCreate(result.Error, ctx)
	}
	return nil
}

func (s *securityStorageImpl) DeleteGroupRoles(ctx context.Context, groupCode string, roles []string) error {
	s.l().Mth("delete-group-roles").C(ctx).F(log.FF{"grp": groupCode}).Dbg()
	result := s.c.Db.Instance.Where("group_code = ? and role_code in (?)", groupCode, roles).Delete(&groupRole{})
	if result.Error != nil {
		return errors.ErrSecurityStorageGroupRoleDelete(result.Error, ctx)
	}
	return nil
}

func (s *securityStorageImpl) GetRoleCodesForGroups(ctx context.Context, groups []string) ([]string, error) {
	s.l().Mth("get-role-codes-groups").C(ctx).Dbg()
	query := s.c.Db.Instance.Raw(`select r.code
												from groups g 
													join group_roles gr on g.code = gr.group_code
													join roles r on r.code = gr.role_code
												where g.code in (?) and 
													g.deleted_at is null and 
													gr.deleted_at is null and 
													r.deleted_at is null`, groups)
	var dtos []struct{ Code string }
	err := query.Find(&dtos).Error
	if err != nil {
		return nil, errors.ErrSecurityStorageGroupRoleCodesGet(err, ctx)
	}
	var res []string
	for _, d := range dtos {
		res = append(res, d.Code)
	}
	return res, nil
}

func (s *securityStorageImpl) GroupsWithRoleExists(ctx context.Context, role string) (bool, error) {
	s.l().Mth("groups-with-role-exists").C(ctx).Dbg()
	var r = struct {
		Result *int
	}{}
	res := s.c.Db.Instance.
		Select(`1 as result`).
		Table(`roles r`).
		Where(`r.code = ? and 
	   		 r.deleted_at is null and 
	   		 exists(select 1
	   		  			from group_roles gr
	   		  				 join groups g on gr.group_code = g.code
	   		  			where gr.role_code = r.code and
	   		  				  gr.deleted_at is null and
	   		  				  g.deleted_at is null)`, role).
		Find(&r)
	if res.Error != nil {
		return false, errors.ErrSecurityStorageGroupsRoleExists(res.Error, ctx)
	}
	return res.RowsAffected > 0, nil
}

func (s *securityStorageImpl) CreateResource(ctx context.Context, resource *domain.Resource) error {
	s.l().Mth("create-resource").C(ctx).F(log.FF{"grp": resource.Code}).Dbg()
	dto := s.toResourceDto(resource)
	result := s.c.Db.Instance.Create(dto)
	if result.Error != nil {
		return errors.ErrSecurityStorageResourceCreate(result.Error, ctx)
	}
	return nil
}

func (s *securityStorageImpl) UpdateResource(ctx context.Context, resource *domain.Resource) error {
	s.l().Mth("update-resource").C(ctx).F(log.FF{"role": resource.Code}).Dbg()
	dto := s.toResourceDto(resource)
	result := s.c.Db.Instance.Save(dto)
	if result.Error != nil {
		return errors.ErrSecurityStorageResourceUpdate(result.Error, ctx)
	}
	return nil
}

func (s *securityStorageImpl) DeleteResource(ctx context.Context, code string) error {
	s.l().Mth("delete-resource").C(ctx).F(log.FF{"resource": code}).Dbg()
	result := s.c.Db.Instance.Delete(&resource{Code: code})
	if result.Error != nil {
		return errors.ErrSecurityStorageResourceDelete(result.Error, ctx)
	}
	return nil
}

func (s *securityStorageImpl) GetResource(ctx context.Context, code string) (bool, *domain.Resource, error) {
	s.l().Mth("get-resource").C(ctx).F(log.FF{"resource": code}).Dbg()
	dto := &resource{Code: code}
	if res := s.c.Db.Instance.Limit(1).Find(&dto); res.Error == nil {
		if res.RowsAffected == 0 {
			return false, nil, nil
		} else {
			return true, s.toResourceDomain(dto), nil
		}
	} else {
		return false, nil, errors.ErrSecurityStorageResourceGet(res.Error, ctx)
	}
}

func (s *securityStorageImpl) GetAllResources(ctx context.Context) ([]*domain.Resource, error) {
	s.l().Mth("get-resources").C(ctx).Dbg()
	var dtos []*resource
	if res := s.c.Db.Instance.Find(&dtos); res.Error == nil {
		return s.toResourcesDomain(dtos), nil
	} else {
		return nil, errors.ErrSecurityStorageResourcesGet(res.Error, ctx)
	}
}

func (s *securityStorageImpl) ResourceExplicitPermissionsExists(ctx context.Context, code string) (bool, error) {
	s.l().Mth("resource-permissions-exists").C(ctx).Dbg()
	result := s.c.Db.Instance.Where("resource_code = ?", code).Limit(1).Find(&permission{})
	if result.Error != nil {
		return false, errors.ErrSecurityStoragePermissionExists(result.Error, ctx)
	}
	return result.RowsAffected > 0, nil
}

func (s *securityStorageImpl) UpsertPermissions(ctx context.Context, resource, role string, permissions *domain.Permissions) error {
	s.l().Mth("upsert-permissions").C(ctx).Dbg()
	dto := s.toPermissionDto(resource, role, permissions)
	found := &permission{}
	err := s.c.Db.Instance.Where("resource_code = ? and role_code = ?", resource, role).First(&found).Error
	if err != nil {
		if goErrors.Is(err, gorm.ErrRecordNotFound) {
			s.c.Db.Instance.Create(&dto)
		} else {
			return errors.ErrSecurityStoragePermissionUpsert(err, ctx)
		}
	} else {
		err = s.c.Db.Instance.Model(&dto).
			Where("resource_code = ? and role_code = ? and deleted_at is null", resource, role).
			Updates(permission{
				AllowR: dto.AllowR,
				AllowW: dto.AllowW,
				AllowX: dto.AllowX,
				AllowD: dto.AllowD,
				DenyR:  dto.DenyR,
				DenyW:  dto.DenyW,
				DenyX:  dto.DenyX,
				DenyD:  dto.DenyD,
			}).Error
		if err != nil {
			return errors.ErrSecurityStoragePermissionUpsert(err, ctx)
		}
	}
	return nil
}

func (s *securityStorageImpl) DeletePermissions(ctx context.Context, resource, role string) error {
	s.l().Mth("delete-permissions").C(ctx).Dbg()
	result := s.c.Db.Instance.Where("resource_code = ? and role_code = ?", resource, role).Delete(&permission{})
	if result.Error != nil {
		return errors.ErrSecurityStoragePermissionDelete(result.Error, ctx)
	}
	return nil
}

func (s *securityStorageImpl) GetPermissions(ctx context.Context, resource string, roles []string) ([]*domain.Permissions, error) {
	s.l().Mth("get-permissions").C(ctx).Dbg()
	var dtos []*permission
	if res := s.c.Db.Instance.Where("resource_code = ? and role_code in (?)", resource, roles).Find(&dtos); res.Error == nil {
		return s.toPermissionsDomain(dtos), nil
	} else {
		return nil, errors.ErrSecurityStoragePermissionGet(res.Error, ctx)
	}
}

func (s *securityStorageImpl) UpsertWildcardPermissions(ctx context.Context, resourcePattern, role string, permissions *domain.Permissions) error {
	s.l().Mth("upsert-wc-permissions").C(ctx).Dbg()
	dto := s.toWcPermissionDto(resourcePattern, role, permissions)
	found := &wildcardPermission{}
	err := s.c.Db.Instance.Where("resource_pattern = ? and role_code = ?", resourcePattern, role).First(&found).Error
	if err != nil {
		if goErrors.Is(err, gorm.ErrRecordNotFound) {
			s.c.Db.Instance.Create(&dto)
		} else {
			return errors.ErrSecurityStoragePermissionUpsert(err, ctx)
		}
	} else {
		err = s.c.Db.Instance.Model(&dto).
			Where("resource_pattern = ? and role_code = ? and deleted_at is null", resourcePattern, role).
			Updates(permission{
				AllowR: dto.AllowR,
				AllowW: dto.AllowW,
				AllowX: dto.AllowX,
				AllowD: dto.AllowD,
				DenyR:  dto.DenyR,
				DenyW:  dto.DenyW,
				DenyX:  dto.DenyX,
				DenyD:  dto.DenyD,
			}).Error
		if err != nil {
			return errors.ErrSecurityStoragePermissionUpsert(err, ctx)
		}
	}
	return nil
}

func (s *securityStorageImpl) DeleteWildcardPermissions(ctx context.Context, resourcePattern, role string) error {
	s.l().Mth("delete-wc-permissions").C(ctx).Dbg()
	result := s.c.Db.Instance.Where("resource_pattern = ? and role_code = ?", resourcePattern, role).Delete(&wildcardPermission{})
	if result.Error != nil {
		return errors.ErrSecurityStoragePermissionDelete(result.Error, ctx)
	}
	return nil
}

func (s *securityStorageImpl) GetWildcardPermissions(ctx context.Context, resource string, roles []string) ([]*domain.Permissions, error) {
	s.l().Mth("get-wc-permissions").C(ctx).Dbg()
	var dtos []*wildcardPermission
	if res := s.c.Db.Instance.Where("? ilike replace(resource_pattern, '*', '%') and role_code in (?)", resource, roles).Find(&dtos); res.Error == nil {
		return s.toWcPermissionsDomain(dtos), nil
	} else {
		return nil, errors.ErrSecurityStoragePermissionGet(res.Error, ctx)
	}
}

func (s *securityStorageImpl) SearchExplicitPermissions(ctx context.Context, resources []string, roles []string) ([]*domain.RoleResourcePermission, error) {
	s.l().Mth("search-explicit-permissions").C(ctx).Dbg()
	var dtos []*permission
	q := s.c.Db.Instance.Where("1=1")
	if len(resources) > 0 {
		q = q.Where("resource_code in (?)", resources)
	}
	if len(roles) > 0 {
		q = q.Where("role_code in (?)", roles)
	}
	if res := q.Find(&dtos); res.Error == nil {
		return s.toRoleResourcePermissionsDomain(dtos), nil
	} else {
		return nil, errors.ErrSecurityStorageSearchPermissions(res.Error, ctx)
	}
}

func (s *securityStorageImpl) SearchWildcardPermissions(ctx context.Context, roles []string) ([]*domain.RoleWildCardPermission, error) {
	s.l().Mth("search-wc-permissions").C(ctx).Dbg()
	var dtos []*wildcardPermission
	q := s.c.Db.Instance.Where("1=1")
	if len(roles) > 0 {
		q = q.Where("role_code in (?)", roles)
	}
	if res := q.Find(&dtos); res.Error == nil {
		return s.toRoleWcPermissionsDomain(dtos), nil
	} else {
		return nil, errors.ErrSecurityStorageSearchWcPermissions(res.Error, ctx)
	}
}
