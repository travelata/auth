package security

import (
	"context"
	"github.com/travelata/auth/domain"
	"github.com/travelata/auth/errors"
	"github.com/travelata/auth/logger"
	authPb "github.com/travelata/auth/proto"
	"github.com/travelata/kit"
	"github.com/travelata/kit/common"
	"github.com/travelata/kit/log"
)

type securityImpl struct {
	storage     domain.SecurityStorage
	userStorage domain.UserStorage
}

func NewSecurityService(storage domain.SecurityStorage, userStorage domain.UserStorage) domain.SecurityService {
	return &securityImpl{
		storage:     storage,
		userStorage: userStorage,
	}
}

var UserTypeMap = map[string]struct{}{
	authPb.USER_TYPE_READER:    {},
	authPb.USER_TYPE_TECH:      {},
	authPb.USER_TYPE_BLOCKED:   {},
	authPb.USER_TYPE_REGULAR:   {},
	authPb.USER_TYPE_ADMIN:     {},
	authPb.USER_TYPE_SUPPORT:   {},
	authPb.USER_TYPE_MODERATOR: {},
}

func (s *securityImpl) l() log.CLogger {
	return logger.L().Cmp("security-svc")
}

func (s *securityImpl) CreateGroup(ctx context.Context, group *domain.Group) (*domain.Group, error) {
	s.l().C(ctx).Mth("create-group").Dbg()

	// check group
	if group.Code == "" {
		return nil, errors.ErrSecurityGroupCodeEmpty(ctx)
	}
	if group.Name == "" {
		return nil, errors.ErrSecurityGroupNameEmpty(ctx)
	}
	if _, ok := UserTypeMap[group.UserType]; !ok {
		return nil, errors.ErrSecurityGroupUserTypeInvalid(ctx)
	}

	// check group code uniqueness
	found, _, err := s.storage.GetGroup(ctx, group.Code)
	if err != nil {
		return nil, err
	}
	if found {
		return nil, errors.ErrSecurityGroupWithCodeExists(ctx, group.Code)
	}

	now := kit.Now()
	group.CreatedAt = now
	group.UpdatedAt = now
	group.Internal = false

	err = s.storage.CreateGroup(ctx, group)
	if err != nil {
		return nil, err
	}
	return group, nil
}

func (s *securityImpl) UpdateGroup(ctx context.Context, group *domain.Group) (*domain.Group, error) {
	s.l().C(ctx).Mth("update-group").Dbg()

	// check group
	if group.Code == "" {
		return nil, errors.ErrSecurityGroupCodeEmpty(ctx)
	}
	if group.Name == "" {
		return nil, errors.ErrSecurityGroupNameEmpty(ctx)
	}
	if _, ok := UserTypeMap[group.UserType]; !ok {
		return nil, errors.ErrSecurityGroupUserTypeInvalid(ctx)
	}

	// get stored group
	found, storedGrp, err := s.storage.GetGroup(ctx, group.Code)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.ErrSecurityGroupNotFound(ctx, group.Code)
	}

	// internal group cannot be modified
	if storedGrp.Internal {
		return nil, errors.ErrSecurityGroupModifyInternal(ctx, storedGrp.Code)
	}

	group.CreatedAt = storedGrp.CreatedAt
	group.UpdatedAt = kit.Now()
	group.Internal = false
	err = s.storage.UpdateGroup(ctx, group)
	if err != nil {
		return nil, err
	}

	return group, nil
}

func (s *securityImpl) DeleteGroup(ctx context.Context, code string) error {
	s.l().C(ctx).Mth("delete-group").Dbg()

	// get stored group
	found, storedGrp, err := s.storage.GetGroup(ctx, code)
	if err != nil {
		return err
	}
	if !found {
		return errors.ErrSecurityGroupNotFound(ctx, code)
	}

	// internal group cannot be modified
	if storedGrp.Internal {
		return errors.ErrSecurityGroupModifyInternal(ctx, storedGrp.Code)
	}

	// check if no users with the given group exists
	rs, err := s.userStorage.Search(ctx, &domain.UserSearchCriteria{UserGroup: code, PagingRequest: &common.PagingRequest{Size: 1}})
	if err != nil {
		return err
	}
	if rs.Total > 0 {
		return errors.ErrSecurityGroupDeleteUsersExist(ctx, code)
	}

	return s.storage.DeleteGroup(ctx, code)
}

func (s *securityImpl) GetGroup(ctx context.Context, code string) (bool, *domain.Group, error) {
	s.l().C(ctx).Mth("get-group").Dbg()
	return s.storage.GetGroup(ctx, code)
}

func (s *securityImpl) GetGroupsByUserType(ctx context.Context, userType string) ([]*domain.Group, error) {
	s.l().C(ctx).Mth("user-default-group").Dbg()

	groups, err := s.storage.GetGroups(ctx)
	if err != nil {
		return nil, err
	}

	var r []*domain.Group
	for _, grp := range groups {
		if grp.UserType == userType {
			r = append(r, grp)
		}
	}

	return r, nil
}

func (s *securityImpl) GetAllGroups(ctx context.Context) ([]*domain.Group, error) {
	s.l().C(ctx).Mth("get-groups").Dbg()
	return s.storage.GetGroups(ctx)
}

func (s *securityImpl) CreateRole(ctx context.Context, role *domain.Role) (*domain.Role, error) {
	s.l().C(ctx).Mth("create-role").Dbg()

	// check role
	if role.Code == "" {
		return nil, errors.ErrSecurityRoleCodeEmpty(ctx)
	}
	if role.Name == "" {
		return nil, errors.ErrSecurityRoleNameEmpty(ctx)
	}

	// check role code uniqueness
	found, _, err := s.storage.GetRole(ctx, role.Code)
	if err != nil {
		return nil, err
	}
	if found {
		return nil, errors.ErrSecurityRoleWithCodeExists(ctx, role.Code)
	}

	now := kit.Now()
	role.CreatedAt = now
	role.UpdatedAt = now
	role.Internal = false

	err = s.storage.CreateRole(ctx, role)
	if err != nil {
		return nil, err
	}
	return role, nil
}

func (s *securityImpl) UpdateRole(ctx context.Context, role *domain.Role) (*domain.Role, error) {
	s.l().C(ctx).Mth("update-role").Dbg()

	// check role
	if role.Code == "" {
		return nil, errors.ErrSecurityRoleCodeEmpty(ctx)
	}
	if role.Name == "" {
		return nil, errors.ErrSecurityRoleNameEmpty(ctx)
	}

	// get stored role
	found, storedRl, err := s.storage.GetRole(ctx, role.Code)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.ErrSecurityRoleNotFound(ctx, role.Code)
	}

	// internal roles cannot be modified
	if storedRl.Internal {
		return nil, errors.ErrSecurityRoleModifyInternal(ctx, role.Code)
	}

	role.CreatedAt = storedRl.CreatedAt
	role.UpdatedAt = kit.Now()
	role.Internal = false
	err = s.storage.UpdateRole(ctx, role)
	if err != nil {
		return nil, err
	}

	return role, nil
}

func (s *securityImpl) DeleteRole(ctx context.Context, code string) error {
	s.l().C(ctx).Mth("delete-role").Dbg()

	// get stored role
	found, role, err := s.storage.GetRole(ctx, code)
	if err != nil {
		return err
	}
	if !found {
		return errors.ErrSecurityRoleNotFound(ctx, code)
	}

	// internal roles cannot be deleted
	if role.Internal {
		return errors.ErrSecurityRoleModifyInternal(ctx, code)
	}

	// check if no users with the given group exists
	exists, err := s.storage.GroupsWithRoleExists(ctx, code)
	if err != nil {
		return err
	}
	if exists {
		return errors.ErrSecurityRoleDeleteGroupsExist(ctx, code)
	}

	// check if no users with direct roles
	rs, err := s.userStorage.Search(ctx, &domain.UserSearchCriteria{UserRole: code, PagingRequest: &common.PagingRequest{Size: 1}})
	if err != nil {
		return err
	}
	if rs.Total > 0 {
		return errors.ErrSecurityRoleDeleteUsersExist(ctx, code)
	}

	return s.storage.DeleteRole(ctx, code)
}

func (s *securityImpl) GetRole(ctx context.Context, code string) (bool, *domain.Role, error) {
	s.l().C(ctx).Mth("get-role").Dbg()
	return s.storage.GetRole(ctx, code)
}

func (s *securityImpl) GetAllRoles(ctx context.Context) ([]*domain.Role, error) {
	s.l().C(ctx).Mth("delete-roles").Dbg()
	return s.storage.GetAllRoles(ctx)
}

func (s *securityImpl) GetRolesForGroups(ctx context.Context, groups []string) ([]string, error) {
	s.l().C(ctx).Mth("get-roles-groups").Dbg()
	return s.storage.GetRoleCodesForGroups(ctx, groups)
}

func (s *securityImpl) GrantRolesToGroup(ctx context.Context, grpCode string, roles []string) error {
	l := s.l().C(ctx).Mth("grant-roles-group").F(log.FF{"grp": grpCode}).Dbg()

	// get stored group
	found, _, err := s.storage.GetGroup(ctx, grpCode)
	if err != nil {
		return err
	}
	if !found {
		return errors.ErrSecurityGroupNotFound(ctx, grpCode)
	}

	// get roles
	storedRoles, err := s.storage.GetAllRoleCodes(ctx)
	if err != nil {
		return err
	}

	// check all roles found
	rm := make(map[string]struct{}, len(storedRoles))
	for _, r := range storedRoles {
		rm[r] = struct{}{}
	}
	for _, code := range roles {
		if _, ok := rm[code]; !ok {
			return errors.ErrSecurityRoleNotFound(ctx, code)
		}
	}

	// retrieve current roles for the group
	currRoles, err := s.storage.GetRoleCodesForGroups(ctx, []string{grpCode})
	if err != nil {
		return err
	}

	// build list of roles to add
	var rolesToAdd []string
	if len(currRoles) == 0 {
		// if no currently assigned roles
		rolesToAdd = roles
	} else {
		// if there are roles assigned, create only new ones
		rm = make(map[string]struct{}, len(currRoles))
		for _, r := range currRoles {
			rm[r] = struct{}{}
		}
		for _, code := range roles {
			if _, ok := rm[code]; !ok {
				rolesToAdd = append(rolesToAdd, code)
			} else {
				l.WarnF("role %s already granted", code)
			}
		}
	}

	// create group roles
	if len(rolesToAdd) > 0 {
		err = s.storage.CreateGroupRoles(ctx, grpCode, rolesToAdd)
		if err != nil {
			return err
		}
	}
	l.DbgF("%d roles granted", len(rolesToAdd))

	return nil
}

func (s *securityImpl) RevokeRolesFromGroup(ctx context.Context, grpCode string, roles []string) error {
	s.l().C(ctx).Mth("revoke-roles-group").F(log.FF{"grp": grpCode}).Dbg()

	// get stored group
	found, _, err := s.storage.GetGroup(ctx, grpCode)
	if err != nil {
		return err
	}
	if !found {
		return errors.ErrSecurityGroupNotFound(ctx, grpCode)
	}

	// retrieve current roles for the group
	currRoles, err := s.storage.GetRoleCodesForGroups(ctx, []string{grpCode})
	if err != nil {
		return err
	}
	rm := make(map[string]struct{}, len(currRoles))
	for _, r := range currRoles {
		rm[r] = struct{}{}
	}
	for _, code := range roles {
		if _, ok := rm[code]; !ok {
			return errors.ErrSecurityGroupRevokeRoleNotGranted(ctx, grpCode)
		}
	}

	// delete from storage
	return s.storage.DeleteGroupRoles(ctx, grpCode, roles)
}

func (s *securityImpl) CreateResource(ctx context.Context, resource *domain.Resource) (*domain.Resource, error) {
	s.l().C(ctx).Mth("create-resource").Dbg()

	// check resource
	if resource.Code == "" {
		return nil, errors.ErrSecurityResourceCodeEmpty(ctx)
	}
	if resource.Name == "" {
		return nil, errors.ErrSecurityResourceNameEmpty(ctx)
	}

	// check resource code uniqueness
	found, _, err := s.storage.GetResource(ctx, resource.Code)
	if err != nil {
		return nil, err
	}
	if found {
		return nil, errors.ErrSecurityResourceWithCodeExists(ctx, resource.Code)
	}

	now := kit.Now()
	resource.CreatedAt = now
	resource.UpdatedAt = now
	resource.Internal = false

	err = s.storage.CreateResource(ctx, resource)
	if err != nil {
		return nil, err
	}
	return resource, nil
}

func (s *securityImpl) UpdateResource(ctx context.Context, resource *domain.Resource) (*domain.Resource, error) {
	s.l().C(ctx).Mth("update-resource").Dbg()

	// check resource
	if resource.Code == "" {
		return nil, errors.ErrSecurityResourceCodeEmpty(ctx)
	}
	if resource.Name == "" {
		return nil, errors.ErrSecurityResourceNameEmpty(ctx)
	}

	// get stored resource
	found, storedRsc, err := s.storage.GetResource(ctx, resource.Code)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.ErrSecurityResourceNotFound(ctx, resource.Code)
	}

	// internal resources cannot be modified
	if storedRsc.Internal {
		return nil, errors.ErrSecurityResourceModifyInternal(ctx, resource.Code)
	}

	resource.CreatedAt = storedRsc.CreatedAt
	resource.UpdatedAt = kit.Now()
	resource.Internal = false
	err = s.storage.UpdateResource(ctx, resource)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

func (s *securityImpl) DeleteResource(ctx context.Context, code string) error {
	s.l().C(ctx).Mth("delete-resource").Dbg()

	// get stored resource
	found, resource, err := s.storage.GetResource(ctx, code)
	if err != nil {
		return err
	}
	if !found {
		return errors.ErrSecurityResourceNotFound(ctx, code)
	}

	// internal resources cannot be deleted
	if resource.Internal {
		return errors.ErrSecurityResourceModifyInternal(ctx, code)
	}

	// check if no explicit (no wildcard) permissions for the resource exist
	exists, err := s.storage.ResourceExplicitPermissionsExists(ctx, code)
	if err != nil {
		return err
	}
	if exists {
		return errors.ErrSecurityResourceDeletePermissionsExist(ctx, code)
	}

	return s.storage.DeleteResource(ctx, code)
}

func (s *securityImpl) GetResource(ctx context.Context, code string) (bool, *domain.Resource, error) {
	s.l().C(ctx).Mth("get-resource").Dbg()
	return s.storage.GetResource(ctx, code)
}

func (s *securityImpl) GetAllResources(ctx context.Context) ([]*domain.Resource, error) {
	s.l().C(ctx).Mth("get-all-resources").Dbg()
	return s.storage.GetAllResources(ctx)
}

func (s *securityImpl) GetGrantedPermissions(ctx context.Context, resource string, roles []string) (*domain.RWXD, error) {
	s.l().C(ctx).Mth("granted-permissions").F(log.FF{"resource": resource, "roles": roles}).Dbg()

	// get explicit permissions
	explicitPermissions, err := s.storage.GetPermissions(ctx, resource, roles)
	if err != nil {
		return nil, err
	}

	// get wildcard permissions
	wildCardPermissions, err := s.storage.GetWildcardPermissions(ctx, resource, roles)
	if err != nil {
		return nil, err
	}

	permissions := append(explicitPermissions, wildCardPermissions...)

	// calc permissions through explicit and wildcard
	resPermissions := &domain.RWXD{}
	for _, p := range permissions {
		resPermissions.R = (resPermissions.R || p.Allow.R) && !p.Deny.R
		resPermissions.W = (resPermissions.W || p.Allow.W) && !p.Deny.W
		resPermissions.X = (resPermissions.X || p.Allow.X) && !p.Deny.X
		resPermissions.D = (resPermissions.D || p.Allow.D) && !p.Deny.D
	}

	return resPermissions, nil
}

var permMap = map[string]struct{}{
	authPb.R: {},
	authPb.W: {},
	authPb.X: {},
	authPb.D: {},
}

func (s *securityImpl) CheckPermissions(ctx context.Context, resource string, roles []string, requestedPermissions []string) error {
	s.l().C(ctx).Mth("check-permissions").F(log.FF{"resource": resource, "roles": roles}).Dbg()

	if len(requestedPermissions) == 0 {
		return errors.ErrSecurityPermissionsCheckEmptyRequest(ctx, resource)
	}

	// get granted permissions
	grantedPerms, err := s.GetGrantedPermissions(ctx, resource, roles)
	if err != nil {
		return err
	}

	var res = true
	// check all requested permissions are granted
	for _, p := range requestedPermissions {
		// check permission is valid
		if _, ok := permMap[p]; !ok {
			return errors.ErrSecurityPermissionsCheckInvalidRequest(ctx, resource, p)
		}
		switch p {
		case authPb.R:
			res = res && grantedPerms.R
		case authPb.W:
			res = res && grantedPerms.W
		case authPb.X:
			res = res && grantedPerms.X
		case authPb.D:
			res = res && grantedPerms.D
		}
	}

	// if any of requested permissions aren't granted, return error
	if !res {
		return errors.ErrSecurityPermissionsDenied(ctx, resource)
	}
	return nil
}

func (s *securityImpl) GrantPermissions(ctx context.Context, resource, role string, perms *domain.Permissions) error {
	s.l().C(ctx).Mth("grant-permissions").F(log.FF{"resource": resource, "role": role}).Dbg()

	// check role exists
	found, _, err := s.storage.GetRole(ctx, role)
	if err != nil {
		return err
	}
	if !found {
		return errors.ErrSecurityRoleNotFound(ctx, role)
	}

	// check resource exists
	found, _, err = s.storage.GetResource(ctx, resource)
	if err != nil {
		return err
	}
	if !found {
		return errors.ErrSecurityResourceNotFound(ctx, resource)
	}

	// update storage
	return s.storage.UpsertPermissions(ctx, resource, role, perms)

}

func (s *securityImpl) RevokePermissions(ctx context.Context, resource, role string) error {
	s.l().C(ctx).Mth("revoke-permissions").F(log.FF{"resource": resource, "role": role}).Dbg()

	// check if permissions on the given resource and role exists
	perms, err := s.storage.GetPermissions(ctx, resource, []string{role})
	if err != nil {
		return err
	}
	if len(perms) == 0 {
		return errors.ErrSecurityRoleRevokePermissionsNotGranted(ctx, resource, role)
	}

	// update storage
	return s.storage.DeletePermissions(ctx, resource, role)
}

func (s *securityImpl) GetExplicitPermissions(ctx context.Context, resources []string, roles []string) ([]*domain.RoleResourcePermission, error) {
	s.l().C(ctx).Mth("get-explicit-permissions").Dbg()
	return s.storage.SearchExplicitPermissions(ctx, resources, roles)
}

func (s *securityImpl) GetWildCardPermissions(ctx context.Context, roles []string) ([]*domain.RoleWildCardPermission, error) {
	s.l().C(ctx).Mth("get-wc-permissions").Dbg()
	return s.storage.SearchWildcardPermissions(ctx, roles)
}
