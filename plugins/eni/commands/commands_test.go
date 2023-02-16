// +build !integration,!e2e

// Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package commands

import (
	"errors"
	"io/ioutil"
	"os"
	"testing"

	mock_engine "github.com/aws/amazon-ecs-cni-plugins/plugins/eni/engine/mocks"
	"github.com/cihub/seelog"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	eniID          = "eni1"
	deviceName     = "eth1"
	nsName         = "ns1"
	eniIPV4Address = "10.11.12.13/20"
	eniIPV6Address = "2001:db8::68/64"
	eniIPV4Gateway = "10.10.10.10"
	eniIPV6Gateway = "fe80:db9::68"
	macAddress     = "01:23:45:67:89:ab"
)

var (
	eniArgs = &skel.CmdArgs{
		StdinData: []byte(`{"cniVersion": "0.3.0",` +
			`"eni":"` + eniID +
			`", "mac":"` + macAddress +
			`", "ip-addresses":["` + eniIPV4Address + `","` + eniIPV6Address + `"]` +
			` , "gateway-ip-addresses":["` + eniIPV4Gateway + `","` + eniIPV6Gateway + `"]` +
			`}`),
		Netns:  nsName,
		IfName: "eth0",
	}

	eniArgsNoIPV6 = &skel.CmdArgs{
		StdinData: []byte(`{"cniVersion": "0.3.0",` +
			`"eni":"` + eniID +
			`", "mac":"` + macAddress +
			`", "ip-addresses":["` + eniIPV4Address + `"]` +
			` , "gateway-ip-addresses":["` + eniIPV4Gateway + `"]` +
			`}`),
		Netns:  nsName,
		IfName: "eth0",
	}

	eniArgsStayDown = &skel.CmdArgs{
		StdinData: []byte(`{"cniVersion": "0.3.0",` +
			`"eni":"` + eniID +
			`", "mac":"` + macAddress +
			`", "ip-addresses":["` + eniIPV4Address + `","` + eniIPV6Address + `"]` +
			` , "gateway-ip-addresses":["` + eniIPV4Gateway + `","` + eniIPV6Gateway + `"]` +
			` , "stay-down":true` +
			`}`),
		Netns:  nsName,
		IfName: "eth0",
	}
)

func TestAddWithInvalidConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)

	err := add(&skel.CmdArgs{}, mockEngine)
	assert.Error(t, err)
}

func TestAddGetInterfaceDeviceNameFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	gomock.InOrder(
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return("", errors.New("error")),
	)

	err := add(eniArgs, mockEngine)
	assert.Error(t, err)
}

func TestAddSetupContainerNamespaceFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	gomock.InOrder(
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().SetupContainerNamespace(gomock.Any(), deviceName, macAddress,
			[]string{eniIPV4Address, eniIPV6Address},
			[]string{eniIPV4Gateway, eniIPV6Gateway},
			false, false, 0).Return(errors.New("error")),
	)

	err := add(eniArgs, mockEngine)
	assert.Error(t, err)
}

func TestAddSetupContainerNamespaceFailsNoIPV6(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	gomock.InOrder(
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().SetupContainerNamespace(gomock.Any(), deviceName, macAddress,
			[]string{eniIPV4Address}, []string{eniIPV4Gateway},
			false, false, 0).Return(errors.New("error")),
	)

	err := add(eniArgsNoIPV6, mockEngine)
	assert.Error(t, err)
}

func TestAddNoError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	gomock.InOrder(
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().SetupContainerNamespace(gomock.Any(), deviceName, macAddress,
			[]string{eniIPV4Address, eniIPV6Address},
			[]string{eniIPV4Gateway, eniIPV6Gateway},
			false, false, 0).Return(nil),
	)

	err := add(eniArgs, mockEngine)
	assert.NoError(t, err)
}

func TestAddStayDownNoError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	gomock.InOrder(
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().SetupContainerNamespace(gomock.Any(), deviceName, macAddress,
			[]string{eniIPV4Address, eniIPV6Address},
			[]string{eniIPV4Gateway, eniIPV6Gateway},
			false, true, 0).Return(nil),
	)

	err := add(eniArgsStayDown, mockEngine)
	assert.NoError(t, err)
}

func TestAddNoErrorWhenIPV6AddressNotSpecifiedInConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	gomock.InOrder(
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().SetupContainerNamespace(gomock.Any(), deviceName, macAddress,
			[]string{eniIPV4Address}, []string{eniIPV4Gateway},
			false, false, 0).Return(nil),
	)

	err := add(eniArgsNoIPV6, mockEngine)
	assert.NoError(t, err)
}

// TestAddPrintResult tests the add command return compatiable result as cni
func TestAddPrintResult(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Turn off the log for test, as the test needs to read the result returned by the plugin from stdout
	logger, err := seelog.LoggerFromConfigAsString(`
	<seelog minlevel="off"></seelog>
	`)
	assert.NoError(t, err, "create new logger failed")
	err = seelog.ReplaceLogger(logger)
	assert.NoError(t, err, "turn off the logger failed")

	mockEngine := mock_engine.NewMockEngine(ctrl)

	gomock.InOrder(
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().SetupContainerNamespace(gomock.Any(), deviceName, macAddress,
			[]string{eniIPV4Address, eniIPV6Address},
			[]string{eniIPV4Gateway, eniIPV6Gateway},
			false, false, 0).Return(nil),
	)

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err, "redirect os.stdin succeed")

	os.Stdout = w
	err = add(eniArgs, mockEngine)
	assert.NoError(t, err)

	w.Close()
	output, err := ioutil.ReadAll(r)
	require.NoError(t, err, "read from stdin failed")
	os.Stdout = oldStdout

	res, err := version.NewResult("0.3.0", output)
	require.NoError(t, err, "construct result from stdin failed: %s", string(output))
	result, err := current.GetResult(res)
	assert.NoError(t, err, "convert result to current version failed")
	assert.Equal(t, deviceName, result.Interfaces[0].Name)
	assert.Equal(t, macAddress, result.Interfaces[0].Mac)
	assert.Equal(t, 2, len(result.IPs), "result should contains information of both ipv4 and ipv6")
}

func TestAddPrintResultNoIPV6(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Turn off the log for test, as the test needs to read the result returned by the plugin from stdout
	logger, err := seelog.LoggerFromConfigAsString(`
	<seelog minlevel="off"></seelog>
	`)
	assert.NoError(t, err, "create new logger failed")
	err = seelog.ReplaceLogger(logger)
	assert.NoError(t, err, "turn off the logger failed")

	mockEngine := mock_engine.NewMockEngine(ctrl)

	gomock.InOrder(
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().SetupContainerNamespace(gomock.Any(), deviceName, macAddress,
			[]string{eniIPV4Address}, []string{eniIPV4Gateway},
			false, false, 0).Return(nil),
	)

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err, "redirect os.stdin succeed")

	os.Stdout = w
	err = add(eniArgsNoIPV6, mockEngine)
	assert.NoError(t, err)

	w.Close()
	output, err := ioutil.ReadAll(r)
	require.NoError(t, err, "read from stdin failed")
	os.Stdout = oldStdout

	res, err := version.NewResult("0.3.0", output)
	require.NoError(t, err, "construct result from stdin failed")
	result, err := current.GetResult(res)
	assert.NoError(t, err, "convert result to current version failed")
	assert.Equal(t, deviceName, result.Interfaces[0].Name)
	assert.Equal(t, macAddress, result.Interfaces[0].Mac)
	assert.Equal(t, 1, len(result.IPs), "result should only contains information of ipv4")
}
