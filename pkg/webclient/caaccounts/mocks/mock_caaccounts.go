// Code generated by MockGen. DO NOT EDIT.
// Source: ./service/service.go
//
// Generated by this command:
//
//	mockgen -destination=./mocks/mock_caaccounts.go -package=mocks -source=./service/service.go
//

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	service "github.com/Venafi/vcert/v5/pkg/webclient/caaccounts/service"
	gomock "go.uber.org/mock/gomock"
)

// MockCAAccountsServiceWrapper is a mock of CAAccountsServiceWrapper interface.
type MockCAAccountsServiceWrapper struct {
	ctrl     *gomock.Controller
	recorder *MockCAAccountsServiceWrapperMockRecorder
	isgomock struct{}
}

// MockCAAccountsServiceWrapperMockRecorder is the mock recorder for MockCAAccountsServiceWrapper.
type MockCAAccountsServiceWrapperMockRecorder struct {
	mock *MockCAAccountsServiceWrapper
}

// NewMockCAAccountsServiceWrapper creates a new mock instance.
func NewMockCAAccountsServiceWrapper(ctrl *gomock.Controller) *MockCAAccountsServiceWrapper {
	mock := &MockCAAccountsServiceWrapper{ctrl: ctrl}
	mock.recorder = &MockCAAccountsServiceWrapperMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCAAccountsServiceWrapper) EXPECT() *MockCAAccountsServiceWrapperMockRecorder {
	return m.recorder
}

// ListCAAccounts mocks base method.
func (m *MockCAAccountsServiceWrapper) ListCAAccounts(ctx context.Context) (*service.ListCAAccountsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListCAAccounts", ctx)
	ret0, _ := ret[0].(*service.ListCAAccountsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListCAAccounts indicates an expected call of ListCAAccounts.
func (mr *MockCAAccountsServiceWrapperMockRecorder) ListCAAccounts(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListCAAccounts", reflect.TypeOf((*MockCAAccountsServiceWrapper)(nil).ListCAAccounts), ctx)
}
