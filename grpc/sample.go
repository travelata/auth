package grpc

import (
	"context"
	pb "github.com/travelata/auth/proto"
)

func (s *Server) Create(ctx context.Context, rq *pb.CreateSampleRequest) (*pb.Sample, error) {
	sample, err := s.sampleService.Create(ctx, s.toSampleCreateDomain(rq))
	if err != nil {
		return nil, err
	}
	return s.toSamplePb(sample), nil
}

func (s *Server) Update(ctx context.Context, rq *pb.UpdateSampleRequest) (*pb.Sample, error) {
	sample, err := s.sampleService.Update(ctx, s.toSampleUpdateDomain(rq))
	if err != nil {
		return nil, err
	}
	return s.toSamplePb(sample), nil
}

func (s *Server) Get(ctx context.Context, rq *pb.SampleIdRequest) (*pb.Sample, error) {
	found, sample, err := s.sampleService.Get(ctx, rq.Id)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return s.toSamplePb(sample), nil
}

func (s *Server) Delete(ctx context.Context, rq *pb.SampleIdRequest) (*pb.EmptyResponse, error) {
	err := s.sampleService.Delete(ctx, rq.Id)
	if err != nil {
		return nil, err
	}
	return &pb.EmptyResponse{}, nil
}

func (s *Server) Search(ctx context.Context, rq *pb.SearchCriteria) (*pb.SearchResponse, error) {
	rs, err := s.sampleService.Search(ctx, s.toSampleSearchCriteriaDomain(rq))
	if err != nil {
		return nil, err
	}
	return s.toSampleSearchResponsePb(rs), nil
}
