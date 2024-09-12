// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/aws/amazon-ecs-cni-plugins/pkg/execwrapper (interfaces: Cmd,Exec)

// Package mock_execwrapper is a generated GoMock package.
package mock_execwrapper

import (
	io "io"
	reflect "reflect"

	execwrapper "github.com/aws/amazon-ecs-cni-plugins/pkg/execwrapper"
	gomock "github.com/golang/mock/gomock"
)

// MockCmd is a mock of Cmd interface.
type MockCmd struct {
	ctrl     *gomock.Controller
	recorder *MockCmdMockRecorder
}

// MockCmdMockRecorder is the mock recorder for MockCmd.
type MockCmdMockRecorder struct {
	mock *MockCmd
}

// NewMockCmd creates a new mock instance.
func NewMockCmd(ctrl *gomock.Controller) *MockCmd {
	mock := &MockCmd{ctrl: ctrl}
	mock.recorder = &MockCmdMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCmd) EXPECT() *MockCmdMockRecorder {
	return m.recorder
}

// CombinedOutput mocks base method.
func (m *MockCmd) CombinedOutput() ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CombinedOutput")
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CombinedOutput indicates an expected call of CombinedOutput.
func (mr *MockCmdMockRecorder) CombinedOutput() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CombinedOutput", reflect.TypeOf((*MockCmd)(nil).CombinedOutput))
}

// Output mocks base method.
func (m *MockCmd) Output() ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Output")
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Output indicates an expected call of Output.
func (mr *MockCmdMockRecorder) Output() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Output", reflect.TypeOf((*MockCmd)(nil).Output))
}

// Run mocks base method.
func (m *MockCmd) Run() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Run")
	ret0, _ := ret[0].(error)
	return ret0
}

// Run indicates an expected call of Run.
func (mr *MockCmdMockRecorder) Run() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Run", reflect.TypeOf((*MockCmd)(nil).Run))
}

// Start mocks base method.
func (m *MockCmd) Start() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start")
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start.
func (mr *MockCmdMockRecorder) Start() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockCmd)(nil).Start))
}

// StderrPipe mocks base method.
func (m *MockCmd) StderrPipe() (io.ReadCloser, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StderrPipe")
	ret0, _ := ret[0].(io.ReadCloser)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StderrPipe indicates an expected call of StderrPipe.
func (mr *MockCmdMockRecorder) StderrPipe() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StderrPipe", reflect.TypeOf((*MockCmd)(nil).StderrPipe))
}

// StdinPipe mocks base method.
func (m *MockCmd) StdinPipe() (io.WriteCloser, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StdinPipe")
	ret0, _ := ret[0].(io.WriteCloser)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StdinPipe indicates an expected call of StdinPipe.
func (mr *MockCmdMockRecorder) StdinPipe() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StdinPipe", reflect.TypeOf((*MockCmd)(nil).StdinPipe))
}

// StdoutPipe mocks base method.
func (m *MockCmd) StdoutPipe() (io.ReadCloser, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StdoutPipe")
	ret0, _ := ret[0].(io.ReadCloser)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StdoutPipe indicates an expected call of StdoutPipe.
func (mr *MockCmdMockRecorder) StdoutPipe() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StdoutPipe", reflect.TypeOf((*MockCmd)(nil).StdoutPipe))
}

// Wait mocks base method.
func (m *MockCmd) Wait() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Wait")
	ret0, _ := ret[0].(error)
	return ret0
}

// Wait indicates an expected call of Wait.
func (mr *MockCmdMockRecorder) Wait() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Wait", reflect.TypeOf((*MockCmd)(nil).Wait))
}

// MockExec is a mock of Exec interface.
type MockExec struct {
	ctrl     *gomock.Controller
	recorder *MockExecMockRecorder
}

// MockExecMockRecorder is the mock recorder for MockExec.
type MockExecMockRecorder struct {
	mock *MockExec
}

// NewMockExec creates a new mock instance.
func NewMockExec(ctrl *gomock.Controller) *MockExec {
	mock := &MockExec{ctrl: ctrl}
	mock.recorder = &MockExecMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockExec) EXPECT() *MockExecMockRecorder {
	return m.recorder
}

// Command mocks base method.
func (m *MockExec) Command(arg0 string, arg1 ...string) execwrapper.Cmd {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Command", varargs...)
	ret0, _ := ret[0].(execwrapper.Cmd)
	return ret0
}

// Command indicates an expected call of Command.
func (mr *MockExecMockRecorder) Command(arg0 interface{}, arg1 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0}, arg1...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Command", reflect.TypeOf((*MockExec)(nil).Command), varargs...)
}

// LookPath mocks base method.
func (m *MockExec) LookPath(arg0 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LookPath", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LookPath indicates an expected call of LookPath.
func (mr *MockExecMockRecorder) LookPath(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LookPath", reflect.TypeOf((*MockExec)(nil).LookPath), arg0)
}
