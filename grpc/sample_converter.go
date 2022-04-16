package grpc

import (
	"github.com/travelata/auth/domain"
	pb "github.com/travelata/auth/proto"
	"github.com/travelata/kit/common"
)

func (s *Server) toSampleCreateDomain(rq *pb.CreateSampleRequest) *domain.Sample {
	return &domain.Sample{
		Name: rq.Name,
	}
}

func (s *Server) toSampleUpdateDomain(rq *pb.UpdateSampleRequest) *domain.Sample {
	return &domain.Sample{
		Id:   rq.Id,
		Name: rq.Name,
	}
}

func (s *Server) toSamplePb(sample *domain.Sample) *pb.Sample {
	return &pb.Sample{
		Id:   sample.Id,
		Name: sample.Name,
	}
}

func (s *Server) toSamplesPb(samples []*domain.Sample) []*pb.Sample {
	var r []*pb.Sample
	for _, sample := range samples {
		r = append(r, s.toSamplePb(sample))
	}
	return r
}

func (s *Server) toSampleSearchCriteriaDomain(rq *pb.SearchCriteria) *domain.SearchCriteria {
	r := &domain.SearchCriteria{
		PagingRequest: &common.PagingRequest{},
		Name:          rq.Name,
	}
	if rq.Paging != nil {
		r.PagingRequest.Size = int(rq.Paging.Size)
		r.PagingRequest.Index = int(rq.Paging.Index)
	}
	return r
}

func (s *Server) toSampleSearchResponsePb(rs *domain.SearchResponse) *pb.SearchResponse {
	return &pb.SearchResponse{
		Paging: &pb.PagingResponse{
			Index: int32(rs.PagingResponse.Index),
			Total: int32(rs.PagingResponse.Total),
		},
		Samples: s.toSamplesPb(rs.Samples),
	}
}
