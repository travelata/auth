// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package auth

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion7

// SampleServiceClient is the client API for SampleService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type SampleServiceClient interface {
	// Create creates a new sample
	Create(ctx context.Context, in *CreateSampleRequest, opts ...grpc.CallOption) (*Sample, error)
	// Update updates an existent consultant
	Update(ctx context.Context, in *UpdateSampleRequest, opts ...grpc.CallOption) (*Sample, error)
	// Get retrieves a sample by id
	Get(ctx context.Context, in *SampleIdRequest, opts ...grpc.CallOption) (*Sample, error)
	// Delete sample
	Delete(ctx context.Context, in *SampleIdRequest, opts ...grpc.CallOption) (*EmptyResponse, error)
	// Search searches samples
	Search(ctx context.Context, in *SearchCriteria, opts ...grpc.CallOption) (*SearchResponse, error)
}

type sampleServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewSampleServiceClient(cc grpc.ClientConnInterface) SampleServiceClient {
	return &sampleServiceClient{cc}
}

func (c *sampleServiceClient) Create(ctx context.Context, in *CreateSampleRequest, opts ...grpc.CallOption) (*Sample, error) {
	out := new(Sample)
	err := c.cc.Invoke(ctx, "/auth.SampleService/Create", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *sampleServiceClient) Update(ctx context.Context, in *UpdateSampleRequest, opts ...grpc.CallOption) (*Sample, error) {
	out := new(Sample)
	err := c.cc.Invoke(ctx, "/auth.SampleService/Update", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *sampleServiceClient) Get(ctx context.Context, in *SampleIdRequest, opts ...grpc.CallOption) (*Sample, error) {
	out := new(Sample)
	err := c.cc.Invoke(ctx, "/auth.SampleService/Get", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *sampleServiceClient) Delete(ctx context.Context, in *SampleIdRequest, opts ...grpc.CallOption) (*EmptyResponse, error) {
	out := new(EmptyResponse)
	err := c.cc.Invoke(ctx, "/auth.SampleService/Delete", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *sampleServiceClient) Search(ctx context.Context, in *SearchCriteria, opts ...grpc.CallOption) (*SearchResponse, error) {
	out := new(SearchResponse)
	err := c.cc.Invoke(ctx, "/auth.SampleService/Search", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SampleServiceServer is the server API for SampleService service.
// All implementations must embed UnimplementedSampleServiceServer
// for forward compatibility
type SampleServiceServer interface {
	// Create creates a new sample
	Create(context.Context, *CreateSampleRequest) (*Sample, error)
	// Update updates an existent consultant
	Update(context.Context, *UpdateSampleRequest) (*Sample, error)
	// Get retrieves a sample by id
	Get(context.Context, *SampleIdRequest) (*Sample, error)
	// Delete sample
	Delete(context.Context, *SampleIdRequest) (*EmptyResponse, error)
	// Search searches samples
	Search(context.Context, *SearchCriteria) (*SearchResponse, error)
	mustEmbedUnimplementedSampleServiceServer()
}

// UnimplementedSampleServiceServer must be embedded to have forward compatible implementations.
type UnimplementedSampleServiceServer struct {
}

func (UnimplementedSampleServiceServer) Create(context.Context, *CreateSampleRequest) (*Sample, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Create not implemented")
}
func (UnimplementedSampleServiceServer) Update(context.Context, *UpdateSampleRequest) (*Sample, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Update not implemented")
}
func (UnimplementedSampleServiceServer) Get(context.Context, *SampleIdRequest) (*Sample, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Get not implemented")
}
func (UnimplementedSampleServiceServer) Delete(context.Context, *SampleIdRequest) (*EmptyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Delete not implemented")
}
func (UnimplementedSampleServiceServer) Search(context.Context, *SearchCriteria) (*SearchResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Search not implemented")
}
func (UnimplementedSampleServiceServer) mustEmbedUnimplementedSampleServiceServer() {}

// UnsafeSampleServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to SampleServiceServer will
// result in compilation errors.
type UnsafeSampleServiceServer interface {
	mustEmbedUnimplementedSampleServiceServer()
}

func RegisterSampleServiceServer(s grpc.ServiceRegistrar, srv SampleServiceServer) {
	s.RegisterService(&_SampleService_serviceDesc, srv)
}

func _SampleService_Create_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateSampleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SampleServiceServer).Create(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.SampleService/Create",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SampleServiceServer).Create(ctx, req.(*CreateSampleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SampleService_Update_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateSampleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SampleServiceServer).Update(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.SampleService/Update",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SampleServiceServer).Update(ctx, req.(*UpdateSampleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SampleService_Get_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SampleIdRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SampleServiceServer).Get(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.SampleService/Get",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SampleServiceServer).Get(ctx, req.(*SampleIdRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SampleService_Delete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SampleIdRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SampleServiceServer).Delete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.SampleService/Delete",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SampleServiceServer).Delete(ctx, req.(*SampleIdRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SampleService_Search_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SearchCriteria)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SampleServiceServer).Search(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.SampleService/Search",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SampleServiceServer).Search(ctx, req.(*SearchCriteria))
	}
	return interceptor(ctx, in, info, handler)
}

var _SampleService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "auth.SampleService",
	HandlerType: (*SampleServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Create",
			Handler:    _SampleService_Create_Handler,
		},
		{
			MethodName: "Update",
			Handler:    _SampleService_Update_Handler,
		},
		{
			MethodName: "Get",
			Handler:    _SampleService_Get_Handler,
		},
		{
			MethodName: "Delete",
			Handler:    _SampleService_Delete_Handler,
		},
		{
			MethodName: "Search",
			Handler:    _SampleService_Search_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "sample.proto",
}
