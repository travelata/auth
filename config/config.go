package config

import (
	"github.com/travelata/auth/logger"
	"github.com/travelata/auth/meta"
	"github.com/travelata/kit/cache/redis"
	kitConfig "github.com/travelata/kit/config"
	"github.com/travelata/kit/db"
	"github.com/travelata/kit/grpc"
	"github.com/travelata/kit/log"
	"github.com/travelata/kit/monitoring"
	"github.com/travelata/kit/queue"
	"github.com/travelata/kit/search"
	"github.com/travelata/kit/service"
	"os"
	"path/filepath"
)

type Storages struct {
	Es       *search.Config
	Redis    *redis.Config
	Database *db.DbClusterConfig
}

type Token struct {
	Secret              string
	ExpirationPeriodSec uint `config:"expiration-period-sec"`
}

type SecretCode struct {
	ExpirationPeriodSec uint `config:"expiration-period-sec"`
	Mock                string
}

type Auth struct {
	AccessToken  *Token      `config:"access-token"`
	RefreshToken *Token      `config:"refresh-token"`
	SecretCode   *SecretCode `config:"secret-code"`
	Password     *Password   `config:"password"`
}

type Password struct {
	Length      uint `config:"length"`
	NumDigits   uint `config:"num-digits"`
	NumSymbols  uint `config:"num-symbols"`
	NoUpper     bool `config:"no-upper"`
	AllowRepeat bool `config:"allow-repeat"`
}

type Adapter struct {
	Grpc *grpc.ClientConfig
}

type Config struct {
	Grpc       *grpc.ServerConfig
	Storages   *Storages
	Nats       *queue.Config
	Log        *log.Config
	Monitoring *monitoring.Config
	Cluster    *service.Config
	Adapters   map[string]*Adapter
	Auth       *Auth
}

func Load() (*Config, error) {

	// get root folder from env
	rootPath := os.Getenv("PETCAP")
	if rootPath == "" {
		return nil, kitConfig.ErrEnvRootPathNotSet("PETCAP")
	}

	// config path
	configPath := filepath.Join(rootPath, meta.Meta.ServiceCode(), "config.yml")

	// .env path
	envPath := filepath.Join(rootPath, meta.Meta.ServiceCode(), ".env")
	if _, err := os.Stat(envPath); os.IsNotExist(err) {
		envPath = ""
	}

	// load config
	config := &Config{}
	err := kitConfig.NewConfigLoader(logger.LF()).
		WithConfigPath(configPath).
		WithEnvPath(envPath).
		Load(config)

	if err != nil {
		return nil, err
	}
	return config, nil
}
