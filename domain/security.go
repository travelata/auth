package domain

import (
	"context"
	"time"
)

// Group defines business functions of a user
// group may refer to one or multiple roles
type Group struct {
	Code        string    // Code - group code (must be unique)
	Name        string    // Name -  group name
	Description string    // Description - group description
	UserType    string    // UserType - type of users the group can be assign to
	Default     bool      // Default - mark if a group is default one for an user type
	Internal    bool      // Internal - group aren't available for managing on UI
	CreatedAt   time.Time // CreatedAt - created at
	UpdatedAt   time.Time // UpdatedAt - updated at
}

// Role specifies a stable set of permissions
type Role struct {
	Code        string    // Code - role code (must be unique)
	Name        string    // Name -  role name
	Description string    // Description - role description
	Internal    bool      // Internal roles aren't available for managing on UI
	CreatedAt   time.Time // CreatedAt - created at
	UpdatedAt   time.Time // UpdatedAt - updated at
}

// Resource is something we can give permission
type Resource struct {
	Code        string    // Code - resource code (must be unique)
	Name        string    // Name -  resource name
	Description string    // Description - resource description
	Internal    bool      // Internal resource aren't available for managing on UI
	CreatedAt   time.Time // CreatedAt - created at
	UpdatedAt   time.Time // UpdatedAt - updated at
}

// RWXD specify set of permissions
type RWXD struct {
	R bool // R - read
	W bool // W -write
	X bool // X - execute
	D bool // D - delete
}

// Permissions specify allow/deny permissions on resource
type Permissions struct {
	Allow RWXD
	Deny  RWXD
}

// RoleResourcePermission permissions for resource/role
type RoleResourcePermission struct {
	RoleCode     string       // RoleCode - role code
	ResourceCode string       // ResourceCode - resource code
	Permissions  *Permissions // Permissions - permissions
}

// RoleWildCardPermission permissions for resource/role
type RoleWildCardPermission struct {
	RoleCode        string       // RoleCode - role code
	ResourcePattern string       // ResourcePattern - resource pattern
	Permissions     *Permissions // Permissions - permissions
}

type SecurityService interface {
	// CreateGroup creates a group
	CreateGroup(ctx context.Context, group *Group) (*Group, error)
	// UpdateGroup updates a group
	UpdateGroup(ctx context.Context, group *Group) (*Group, error)
	// DeleteGroup deletes a group
	DeleteGroup(ctx context.Context, code string) error
	// GetGroup retrieves a group by code
	GetGroup(ctx context.Context, code string) (bool, *Group, error)
	// GetGroupsByUserType retrieves groups for user type
	GetGroupsByUserType(ctx context.Context, userType string) ([]*Group, error)
	// GetAllGroups retrieves all not deleted groups
	GetAllGroups(ctx context.Context) ([]*Group, error)

	// CreateRole creates a role
	CreateRole(ctx context.Context, role *Role) (*Role, error)
	// UpdateRole updates a role
	UpdateRole(ctx context.Context, role *Role) (*Role, error)
	// DeleteRole deletes a role
	DeleteRole(ctx context.Context, code string) error
	// GetRole retrieves a role by code
	GetRole(ctx context.Context, code string) (bool, *Role, error)
	// GetAllRoles retrieves all not deleted roles
	GetAllRoles(ctx context.Context) ([]*Role, error)
	// GetRolesForGroups retrieves roles assigned on groups
	GetRolesForGroups(ctx context.Context, groups []string) ([]string, error)

	// GrantRolesToGroup grants roles to group
	GrantRolesToGroup(ctx context.Context, code string, roles []string) error
	// RevokeRolesFromGroup revokes roles from group
	RevokeRolesFromGroup(ctx context.Context, code string, roles []string) error

	// CreateResource creates a resource
	CreateResource(ctx context.Context, resource *Resource) (*Resource, error)
	// UpdateResource updates a resource
	UpdateResource(ctx context.Context, resource *Resource) (*Resource, error)
	// DeleteResource deletes a resource
	DeleteResource(ctx context.Context, code string) error
	// GetResource retrieves a resource by code
	GetResource(ctx context.Context, code string) (bool, *Resource, error)
	// GetAllResources retrieves all not deleted resources
	GetAllResources(ctx context.Context) ([]*Resource, error)

	// GrantPermissions grants permissions to the role
	// allow permissions specify permissions which are allowed for the role. Allow permissions are summarized for user/role (logical OR)
	// deny permissions specify permissions which are prohibited for the role. Deny permissions aren't summarized for user/role (logical NOT AND)
	// The use case of deny permission is when we want an access to be denied no matter which role is granted
	// e.g an user granted to roles on a resource: Role1: R(allow), W(allow) Role2: W(deny) -> R access is allowed, W access is denied
	GrantPermissions(ctx context.Context, resource, role string, permissions *Permissions) error
	// RevokePermissions revokes permissions from the role on resource
	// it removes all permissions for the given resource and role
	RevokePermissions(ctx context.Context, resource, role string) error
	// GetGrantedPermissions calculates permissions on resource for set of roles and apply allow/deny logic
	GetGrantedPermissions(ctx context.Context, resource string, roles []string) (*RWXD, error)
	// CheckPermissions returns error if requested permissions isn't granted
	CheckPermissions(ctx context.Context, resource string, roles []string, requestedPermissions []string) error
	// GetExplicitPermissions returns permissions on resource / roles setup explicitly
	GetExplicitPermissions(ctx context.Context, resources []string, roles []string) ([]*RoleResourcePermission, error)
	// GetWildCardPermissions returns wildcard permissions on roles
	GetWildCardPermissions(ctx context.Context, roles []string) ([]*RoleWildCardPermission, error)
}
