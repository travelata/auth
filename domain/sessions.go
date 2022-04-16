package domain

import (
	"context"
	"time"
)

// LoginAuthCodeRequest - specifies login params when logging with SMS auth code
type LoginAuthCodeRequest struct {
	Username   string // Phone - phone used as a login
	AuthCode   string // AuthCode code sent to user's phone
	LoginToken string // LoginToken - token issued on send auth code and given to client
}

// LoginPasswordRequest - specifies login params when logging with password
type LoginPasswordRequest struct {
	Username  string // Username - mandatory
	Password  string // Password
	ChatLogin bool   // ChatLogin indicates if login to a chat session needed
}

// SessionToken specifies a session token
type SessionToken struct {
	SessionId             string    // SessionId - session ID
	AccessToken           string    // AccessToken
	AccessTokenExpiresAt  time.Time // AccessTokenExpiresAt - when access token expires
	RefreshToken          string    // RefreshToken
	RefreshTokenExpiresAt time.Time // RefreshToken - when refresh token expires
}

// SessionDetails has all auxiliary info
type SessionDetails struct {
	Browser       string   `json:"browser,omitempty"`
	IsMobile      bool     `json:"isMobile,omitempty"`
	AccessTokenId string   `json:"accessTokenId,omitempty"`
	Roles         []string `json:"roles,omitempty"`
}

// Session specifies session object
type Session struct {
	Id             string          // Id - session id
	UserId         string          // UserId - Id of logged user
	Username       string          // Username - username of logged user
	LoginAt        time.Time       // LoginAt - when session logged in
	LogoutAt       *time.Time      // LogoutAt - when session logged out
	LastActivityAt time.Time       // LastActivityAt - last session activity
	Details        *SessionDetails // Details session details
}

type GetByUserRequest struct {
	UserId   string
	Username string
}

type SendAuthCodeRequest struct {
	Username string
}

// AuthCode specifies auth email code
type AuthCode struct {
	Username   string
	Code       string
	ExpiresAt  time.Time
	LoginToken string
}

// SendAuthCodeResponse response of send auth code
type SendAuthCodeResponse struct {
	LoginToken string // LoginToken - token to verify client
}

// AuthorizationResource requested resource and permissions
type AuthorizationResource struct {
	Resource    string   // Resource  code which is requested
	Permissions []string // Permissions
}

// AuthorizationRequest request for authorization
type AuthorizationRequest struct {
	SessionId              string                   // SessionId - session ID
	AuthorizationResources []*AuthorizationResource // AuthorizationResources requested resources
}

type SessionsService interface {
	// SendAuthCode sends auth code to user's email or bot
	SendAuthCode(ctx context.Context, rq *SendAuthCodeRequest) (*SendAuthCodeResponse, error)
	// LoginPassword logins user with password
	LoginPassword(ctx context.Context, rq *LoginPasswordRequest) (*Session, *SessionToken, error)
	// LoginAuthCode logins user with auth code
	LoginAuthCode(ctx context.Context, rq *LoginAuthCodeRequest) (*Session, *SessionToken, error)
	// Logout logs out all user's sessions
	Logout(ctx context.Context, sid string) error
	// AuthSession verifies session token, returns a session if it's verified
	AuthSession(ctx context.Context, token string) (*Session, error)
	// AuthorizeSession authorizes session (check permission)
	AuthorizeSession(ctx context.Context, rq *AuthorizationRequest) error
	// Get retrieves a session by sid
	Get(ctx context.Context, sid string) (bool, *Session, error)
	// GetByUser retrieves sessions by userId(name)
	GetByUser(ctx context.Context, rq *GetByUserRequest) ([]*Session, error)
	// RefreshToken allows to refresh a session token
	RefreshToken(ctx context.Context, refreshToken string) (*SessionToken, error)
}
