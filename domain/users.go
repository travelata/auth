package domain

import (
	"context"
	"github.com/travelata/auth/config"
	"github.com/travelata/kit/common"
	"time"
)

const (
	AuthTypeCode     = "code"     // login via code
	AuthTypePassword = "password" // login via password
	AuthTypeNone     = "none"     // login isn't available
)

type UserDetails struct {
	FirstName string   `json:"firstName"`
	LastName  string   `json:"lastName"`
	Email     string   `json:"email"`
	Avatar    string   `json:"avatar"`
	Introduce string   `json:"introduce"`
	Bio       string   `json:"bio"`
	Links     []*Link  `json:"links"`
	Groups    []string `json:"groups"` // Groups - assigned groups
	Roles     []string `json:"roles"`  // Roles - user direct roles
}

type Link struct {
	Network string `json:"network"`
	Link    string `json:"link"`
}

// User is a domain object
type User struct {
	Id        string
	Username  string
	Type      string
	AuthType  string
	Status    string
	Password  string
	Details   *UserDetails
	Reason    string
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

type CreateUserRequest struct {
	FirstName string
	LastName  string
	Type      string
	Email     string
	Password  string
	Avatar    string
	Groups    []string
	Introduce string
	Username  string
}

// UserSearchCriteria defines users search criteria
type UserSearchCriteria struct {
	*common.PagingRequest        // paging support
	UserType              string // Name - search by name
	Username              string
	UserGroup             string
	UserRole              string
	Status                string
	Email                 string
}

// UserSearchResponse represents result of users search
type UserSearchResponse struct {
	*common.PagingResponse         // paging support
	Users                  []*User // Samples - list of samples found
}

type BlockUserRequest struct {
	UserId string
	Reason string
}

type UserService interface {
	// Init inits service with config data
	Init(c *config.Config)
	// Create creates a new user
	Create(ctx context.Context, request *CreateUserRequest) (*User, error)
	// GetByUsername retrieve user by username
	GetByUsername(ctx context.Context, un string) (bool, *User, error)
	// Get retrieves a user by id
	Get(ctx context.Context, id string) (bool, *User, error)
	// GetByIds retrieve users by ids
	GetByIds(ctx context.Context, ids []string) ([]*User, error)
	// UpdateUserDetails updates an existent user details
	UpdateUserDetails(ctx context.Context, userId string, details *UserDetails) (*User, error)
	// UpdateUserIntroduce updates an existent user introduce
	UpdateUserIntroduce(ctx context.Context)
	// SetStatus set user status
	SetStatus(ctx context.Context, userId string, status string) (*User, error)
	// Search searches for users
	Search(ctx context.Context, cr *UserSearchCriteria) (*UserSearchResponse, error)
	// AddGroups adds user to the given groups
	AddGroups(ctx context.Context, userId string, groups []string) (*User, error)
	// DeleteGroups deletes user from groups
	DeleteGroups(ctx context.Context, userId string, groups []string) (*User, error)
	// GrantRoles grants direct roles to user
	GrantRoles(ctx context.Context, userId string, roles []string) (*User, error)
	// RevokeRoles revokes direct roles from user
	RevokeRoles(ctx context.Context, userId string, roles []string) (*User, error)
	// ResetPassword resets user password to auto-generated
	ResetPassword(ctx context.Context, userId string) error
}
