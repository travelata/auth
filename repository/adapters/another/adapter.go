package another

import (
	"context"
	"github.com/travelata/auth/config"
	"github.com/travelata/auth/domain"
	kitGrpc "github.com/travelata/kit/grpc"
)

type Adapter interface {
	domain.AnotherServiceRepository
	Init(cfg *config.Adapter) error
	Close()
}

type adapterImpl struct {
	// Grpc client, uncomment and put your own correct client
	// pb.AnotherClient
	client *kitGrpc.Client
}

func NewAdapter() Adapter {
	return &adapterImpl{}
}

func (a *adapterImpl) Init(cfg *config.Adapter) error {
	cl, err := kitGrpc.NewClient(cfg.Grpc)
	if err != nil {
		return err
	}
	a.client = cl

	// Uncomment and put your own gRPC client
	// a.AnotherClient = pb.NewAnotherClient(cl.Conn)

	return nil
}

func (a *adapterImpl) Close() {
	_ = a.client.Conn.Close()
}

func (a *adapterImpl) Do(ctx context.Context) error {
	// Uncomment and put your own gRPC client call
	// return a.AnotherClient.Do(ctx)
	return nil
}
