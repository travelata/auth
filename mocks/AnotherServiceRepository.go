// Code generated by mockery v2.7.4. DO NOT EDIT.

package mocks

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// AnotherServiceRepository is an autogenerated mock type for the AnotherServiceRepository type
type AnotherServiceRepository struct {
	mock.Mock
}

// Do provides a mock function with given fields: ctx
func (_m *AnotherServiceRepository) Do(ctx context.Context) error {
	ret := _m.Called(ctx)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context) error); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}