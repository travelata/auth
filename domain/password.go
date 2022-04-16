package domain

import (
	"context"
	"github.com/travelata/auth/config"
)

// PasswordGenerator provides an access to generate password function
type PasswordGenerator interface {
	// Generate generate password
	Generate(context.Context) (string, error)
	// Init init generator
	Init(*config.Password)
}
