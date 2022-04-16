package domain

import (
	"context"
	"time"
)

type UserStorage interface {
	// Create creates a new user
	Create(ctx context.Context, user *User) error
	// Update updates an existent user
	Update(ctx context.Context, user *User) error
	// GetByUsername retrieves a user by username
	GetByUsername(ctx context.Context, un string) (bool, *User, error)
	// Get retrieves a user by id
	Get(ctx context.Context, id string) (bool, *User, error)
	// GetByIds retrieves a users by ids
	GetByIds(ctx context.Context, ids []string) ([]*User, error)
	// Search searches for users
	Search(ctx context.Context, cr *UserSearchCriteria) (*UserSearchResponse, error)
}

// SecurityStorage provides storing security data
type SecurityStorage interface {
	// CreateGroup creates a group
	CreateGroup(ctx context.Context, group *Group) error
	// UpdateGroup updates a group
	UpdateGroup(ctx context.Context, group *Group) error
	// DeleteGroup deletes a group
	DeleteGroup(ctx context.Context, code string) error
	// GetGroup retrieves a group by code
	GetGroup(ctx context.Context, code string) (bool, *Group, error)
	// GetGroups retrieves all not deleted groups
	GetGroups(ctx context.Context) ([]*Group, error)

	// CreateRole creates a role
	CreateRole(ctx context.Context, role *Role) error
	// UpdateRole updates a role
	UpdateRole(ctx context.Context, role *Role) error
	// DeleteRole deletes a role
	DeleteRole(ctx context.Context, code string) error
	// GetRole retrieves a role by code
	GetRole(ctx context.Context, code string) (bool, *Role, error)
	// GetAllRoles retrieves all not deleted roles
	GetAllRoles(ctx context.Context) ([]*Role, error)
	// GetAllRoleCodes retrieves all role codes
	GetAllRoleCodes(ctx context.Context) ([]string, error)

	// CreateResource creates a resource
	CreateResource(ctx context.Context, resource *Resource) error
	// UpdateResource updates a resource
	UpdateResource(ctx context.Context, resource *Resource) error
	// DeleteResource deletes a resource
	DeleteResource(ctx context.Context, code string) error
	// GetResource retrieves a resource by code
	GetResource(ctx context.Context, code string) (bool, *Resource, error)
	// GetAllResources retrieves all not deleted resources
	GetAllResources(ctx context.Context) ([]*Resource, error)
	// ResourceExplicitPermissionsExists checks if there are explicit (no wildcard) permissions on the resource
	ResourceExplicitPermissionsExists(ctx context.Context, code string) (bool, error)

	// CreateGroupRoles creates group-roles relations
	CreateGroupRoles(ctx context.Context, groupCode string, roles []string) error
	// DeleteGroupRoles deletes group-roles relations
	DeleteGroupRoles(ctx context.Context, groupCode string, roles []string) error
	// GetRoleCodesForGroups retrieves role codes for groups
	GetRoleCodesForGroups(ctx context.Context, groups []string) ([]string, error)
	// GroupsWithRoleExists checks if there are groups with assigned role
	GroupsWithRoleExists(ctx context.Context, role string) (bool, error)

	// UpsertPermissions create or update permissions
	UpsertPermissions(ctx context.Context, resource, role string, permissions *Permissions) error
	// DeletePermissions deletes permissions
	DeletePermissions(ctx context.Context, resource, role string) error
	// GetPermissions retrieves permissions granted to roles on resource
	GetPermissions(ctx context.Context, resource string, roles []string) ([]*Permissions, error)

	// UpsertWildcardPermissions create or update wildcard permissions
	UpsertWildcardPermissions(ctx context.Context, resourcePattern, role string, permissions *Permissions) error
	// DeleteWildcardPermissions deletes wildcard permissions
	DeleteWildcardPermissions(ctx context.Context, resourcePattern, role string) error
	// GetWildcardPermissions retrieves wildcard permissions granted to roles on resource
	GetWildcardPermissions(ctx context.Context, resource string, roles []string) ([]*Permissions, error)

	// SearchExplicitPermissions returns permissions on resource / roles setup explicitly
	SearchExplicitPermissions(ctx context.Context, resources []string, roles []string) ([]*RoleResourcePermission, error)
	// SearchWildcardPermissions returns wildcard permissions on roles
	SearchWildcardPermissions(ctx context.Context, roles []string) ([]*RoleWildCardPermission, error)
}

type SessionStorage interface {
	// Get - retrieves session by SID
	Get(ctx context.Context, sid string) (bool, *Session, error)
	// GetByUser - retrieves all user's sessions
	GetByUser(ctx context.Context, uid string) ([]*Session, error)
	// CreateSession creates a new session in store
	CreateSession(ctx context.Context, session *Session, token *SessionToken) error
	// UpdateLastActivity updates last activity date of the session
	UpdateLastActivity(ctx context.Context, sid string, lastActivity time.Time) error
	// Logout marks session as logged out
	Logout(ctx context.Context, sid string, logoutAt time.Time) error
}

type AuthCodeStorage interface {
	// Set persists auth code for the user
	Set(ctx context.Context, code *AuthCode) error
	// Get retrieves auth code
	Get(ctx context.Context, email string) (bool, *AuthCode, error)
}

type CommunicationRepository interface {
	Send(ctx context.Context)
}
