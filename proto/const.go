package auth

const (
	USER_TYPE_MODERATOR = "moderator"
	USER_TYPE_ADMIN     = "admin"
	USER_TYPE_SUPPORT   = "support"
	USER_TYPE_TECH      = "tech"
	USER_TYPE_REGULAR   = "regular"
	USER_TYPE_READER    = "reader"
	USER_TYPE_BLOCKED   = "blocked"

	USER_STATUS_DRAFT   = "draft"   // user cannot do anything in the system
	USER_STATUS_ACTIVE  = "active"  // user can do everything permitted by its roles
	USER_STATUS_LOCKED  = "locked"  // user cannot do anything in the system
	USER_STATUS_DELETED = "deleted" // user cannot do anything in the system

	// permissions
	R = "r" // R read
	W = "w" // W write
	X = "x" // X execute
	D = "d" // D delete
)
