//go:build integration
// +build integration

package grpc

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/travelata/auth/config"
	pb "github.com/travelata/auth/proto"
	kitContext "github.com/travelata/kit/context"
	kitGrpc "github.com/travelata/kit/grpc"
	"testing"
)

type sampleGrpcTestSuite struct {
	suite.Suite
	ctx        context.Context
	sampleAuth pb.SampleServiceClient
}

func (s *sampleGrpcTestSuite) SetupSuite() {

	// setup context
	s.ctx = kitContext.NewRequestCtx().Test().ToContext(context.Background())

	// load config
	cfg, err := config.Load()
	if err != nil {
		s.T().Fatal(err)
	}

	// create GRPC client
	cl, err := kitGrpc.NewClient(&kitGrpc.ClientConfig{Host: cfg.Grpc.Host, Port: cfg.Grpc.Port})
	if err != nil {
		s.T().Fatal(err)
	}
	s.sampleAuth = pb.NewSampleServiceClient(cl.Conn)
}

func TestSampleSuite(t *testing.T) {
	suite.Run(t, new(sampleGrpcTestSuite))
}

func (s *sampleGrpcTestSuite) getCreateRequest() *pb.CreateSampleRequest {
	return &pb.CreateSampleRequest{
		Name: "name",
	}
}

func (s *sampleGrpcTestSuite) Test_CRUD() {

	// create a new consultant
	sample, err := s.sampleAuth.Create(s.ctx, s.getCreateRequest())
	if err != nil {
		s.T().Fatal(err)
	}
	assert.NotEmpty(s.T(), sample.Id)

	// get by Id
	sample, err = s.sampleAuth.Get(s.ctx, &pb.SampleIdRequest{Id: sample.Id})
	if err != nil {
		s.T().Fatal()
	}
	assert.NotEmpty(s.T(), sample)
	assert.NotEmpty(s.T(), sample.Id)

	// set status to active
	sample, err = s.sampleAuth.Update(s.ctx, &pb.UpdateSampleRequest{
		Id:   sample.Id,
		Name: "another name",
	})
	if err != nil {
		s.T().Fatal()
	}
	assert.Equal(s.T(), "another name", sample.Name)

	// delete sample
	_, err = s.sampleAuth.Delete(s.ctx, &pb.SampleIdRequest{Id: sample.Id})
	if err != nil {
		s.T().Fatal()
	}
}
