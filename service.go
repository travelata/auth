package auth

import (
	"context"
	"github.com/travelata/auth/config"
	"github.com/travelata/auth/domain"
	"github.com/travelata/auth/domain/impl/password"
	"github.com/travelata/auth/domain/impl/security"
	"github.com/travelata/auth/domain/impl/sessions"
	"github.com/travelata/auth/domain/impl/users"
	"github.com/travelata/auth/grpc"
	"github.com/travelata/auth/logger"
	"github.com/travelata/auth/meta"
	"github.com/travelata/auth/repository/storage"
	"github.com/travelata/kit/monitoring"
	"github.com/travelata/kit/queue"
	"github.com/travelata/kit/queue/stan"
	"github.com/travelata/kit/service"
)

type serviceImpl struct {
	service.Cluster
	cfg             *config.Config
	monitoring      monitoring.MetricsServer
	usersService    domain.UserService
	securityService domain.SecurityService
	sessionsService domain.SessionsService
	grpc            *grpc.Server
	storageAdapter  storage.Adapter
	queue           queue.Queue
}

// New creates a new instance of the service
func New() service.Service {

	s := &serviceImpl{
		Cluster:    service.NewCluster(logger.LF(), meta.Meta),
		monitoring: monitoring.NewMetricsServer(logger.LF()),
	}

	s.queue = stan.New(logger.LF())
	s.storageAdapter = storage.NewAdapter()

	userStorage := s.storageAdapter.GetUsersStorage()
	s.securityService = security.NewSecurityService(s.storageAdapter.GetSecurityStorage(), userStorage)
	s.usersService = users.NewUserService(password.New(), userStorage, s.securityService)

	return s
}

func (s *serviceImpl) GetCode() string {
	return meta.Meta.ServiceCode()
}

// Init does all initializations
func (s *serviceImpl) Init(ctx context.Context) error {

	// load config
	var err error
	s.cfg, err = config.Load()
	if err != nil {
		return err
	}

	// set log config
	logger.Logger.Init(s.cfg.Log)

	// init cluster
	if err := s.Cluster.Init(s.cfg.Cluster, s.cfg.Nats.Host, s.cfg.Nats.Port, s.onClusterLeaderChanged(ctx)); err != nil {
		return err
	}

	// init storage
	if err := s.storageAdapter.Init(s.cfg.Storages); err != nil {
		return err
	}

	s.sessionsService = sessions.NewSessionService(s.usersService,
		s.securityService,
		s.cfg.Auth,
		s.storageAdapter.GetSessionsStorage(),
		s.storageAdapter.GetAuthCodeStorage())

	// init grpc server
	if err := s.grpc.Init(s.cfg.Grpc); err != nil {
		return err
	}

	// init user service
	s.usersService.Init(s.cfg)

	// open Queue connection
	if err := s.queue.Open(ctx, meta.Meta.InstanceId(), s.cfg.Nats); err != nil {
		return err
	}

	// init monitoring
	if s.cfg.Monitoring.Enabled {
		if err := s.monitoring.Init(s.cfg.Monitoring); err != nil {
			return err
		}
	}

	return nil

}

func (s *serviceImpl) onClusterLeaderChanged(ctx context.Context) service.OnLeaderChangedEvent {

	// if the current node is getting a leader, run daemons
	return func(l bool) {
		if l {
			// do something if the node is turned into a leader
			logger.L().C(ctx).Cmp("cluster").Mth("on-leader-change").Dbg("leader")
		}
	}

}

func (s *serviceImpl) Start(ctx context.Context) error {

	// start cluster
	if err := s.Cluster.Start(); err != nil {
		return err
	}

	// serve gRPC connection
	s.grpc.ListenAsync()

	// listen for scraping metrics
	if s.cfg.Monitoring.Enabled {
		s.monitoring.Listen()
	}

	return nil
}

func (s *serviceImpl) Close(ctx context.Context) {
	s.Cluster.Close()
	_ = s.queue.Close()
	s.storageAdapter.Close()
	s.grpc.Close()
	if s.cfg.Monitoring.Enabled {
		s.monitoring.Close()
	}
}
