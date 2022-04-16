// Code generated by mockery v2.7.4. DO NOT EDIT.

package mocks

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
	auth "github.com/travelata/auth/proto"
)

// SampleServiceServer is an autogenerated mock type for the SampleServiceServer type
type SampleServiceServer struct {
	mock.Mock
}

// Create provides a mock function with given fields: _a0, _a1
func (_m *SampleServiceServer) Create(_a0 context.Context, _a1 *auth.CreateSampleRequest) (*auth.Sample, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *auth.Sample
	if rf, ok := ret.Get(0).(func(context.Context, *auth.CreateSampleRequest) *auth.Sample); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*auth.Sample)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *auth.CreateSampleRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Delete provides a mock function with given fields: _a0, _a1
func (_m *SampleServiceServer) Delete(_a0 context.Context, _a1 *auth.SampleIdRequest) (*auth.EmptyResponse, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *auth.EmptyResponse
	if rf, ok := ret.Get(0).(func(context.Context, *auth.SampleIdRequest) *auth.EmptyResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*auth.EmptyResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *auth.SampleIdRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Get provides a mock function with given fields: _a0, _a1
func (_m *SampleServiceServer) Get(_a0 context.Context, _a1 *auth.SampleIdRequest) (*auth.Sample, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *auth.Sample
	if rf, ok := ret.Get(0).(func(context.Context, *auth.SampleIdRequest) *auth.Sample); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*auth.Sample)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *auth.SampleIdRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Search provides a mock function with given fields: _a0, _a1
func (_m *SampleServiceServer) Search(_a0 context.Context, _a1 *auth.SearchCriteria) (*auth.SearchResponse, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *auth.SearchResponse
	if rf, ok := ret.Get(0).(func(context.Context, *auth.SearchCriteria) *auth.SearchResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*auth.SearchResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *auth.SearchCriteria) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Update provides a mock function with given fields: _a0, _a1
func (_m *SampleServiceServer) Update(_a0 context.Context, _a1 *auth.UpdateSampleRequest) (*auth.Sample, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *auth.Sample
	if rf, ok := ret.Get(0).(func(context.Context, *auth.UpdateSampleRequest) *auth.Sample); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*auth.Sample)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *auth.UpdateSampleRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mustEmbedUnimplementedSampleServiceServer provides a mock function with given fields:
func (_m *SampleServiceServer) mustEmbedUnimplementedSampleServiceServer() {
	_m.Called()
}