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
	eniIPV4Address               = "10.11.12.13"
	eniIPV6Address               = "2001:db8::68"
	eniID                        = "eni1"
	deviceName                   = "eth1"
	nsName                       = "ns1"
	eniIPV4Gateway               = "10.10.10.10"
	eniIPV6Gateway               = "2001:db9::68"
	eniIPV4SubnetMask            = "20"
	eniIPV6SubnetMask            = "32"
	macAddress                   = "01:23:45:67:89:ab"
	eniIPV4AddressWithSubnetMask = "10.11.12.13/20"
	eniIPV6AddressWithSubnetMask = "2001:db8::68/32"
)

var (
	eniArgs = &skel.CmdArgs{
		StdinData: []byte(`{"cniVersion": "0.3.0",` +
			`"eni":"` + eniID +
			`", "ipv4-address":"` + eniIPV4Address +
			`", "mac":"` + macAddress +
			`", "ipv6-address":"` + eniIPV6Address +
			`"}`),
		Netns:  nsName,
		IfName: "eth0",
	}

	eniArgsNoIPV6 = &skel.CmdArgs{
		StdinData: []byte(`{"cniVersion": "0.3.0",` +
			`"eni":"` + eniID +
			`", "ipv4-address":"` + eniIPV4Address +
			`", "mac":"` + macAddress +
			`"}`),
		Netns:  nsName,
		IfName: "eth0",
	}

	eniArgsSubnetGateway = &skel.CmdArgs{
		StdinData: []byte(`{"cniVersion": "0.3.0",` +
			`"eni":"` + eniID +
			`", "ipv4-address":"` + eniIPV4Address +
			`", "mac":"` + macAddress +
			`", "subnetgateway-ipv4-address":"` + eniIPV4Gateway + "/" + eniIPV4SubnetMask +
			`"}`),
		Netns:  nsName,
		IfName: "eth0",
	}

	eniArgsStayDown = &skel.CmdArgs{
		StdinData: []byte(`{"cniVersion": "0.3.0",` +
			`"eni":"` + eniID +
			`", "ipv4-address":"` + eniIPV4Address +
			`", "mac":"` + macAddress +
			`", "stay-down":true` +
			`, "ipv6-address":"` + eniIPV6Address +
			`"}`),
		Netns:  nsName,
		IfName: "eth0",
	}
)

// TODO: Add integration tests for command.Add commands.Del

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

func TestAddGetIPV4GatewayNetmaskFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	gomock.InOrder(
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().GetIPV4GatewayNetmask(macAddress).Return("", "", errors.New("error")),
	)

	err := add(eniArgs, mockEngine)
	assert.Error(t, err)
}

func TestAddGetIPV4GatewayNetmaskFailsNoIPV6(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	gomock.InOrder(
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().GetIPV4GatewayNetmask(macAddress).Return("", "", errors.New("error")),
	)

	err := add(eniArgsNoIPV6, mockEngine)
	assert.Error(t, err)
}

func TestAddGetIPV6SubnetMaskFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	gomock.InOrder(
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().GetIPV4GatewayNetmask(macAddress).Return(eniIPV4Gateway, eniIPV4SubnetMask, nil),
		mockEngine.EXPECT().GetIPV6PrefixLength(macAddress).Return("", errors.New("error")),
	)

	err := add(eniArgs, mockEngine)
	assert.Error(t, err)
}

func TestAddGetIPV6GatewayFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	gomock.InOrder(
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().GetIPV4GatewayNetmask(macAddress).Return(eniIPV4Gateway, eniIPV4SubnetMask, nil),
		mockEngine.EXPECT().GetIPV6PrefixLength(macAddress).Return(eniIPV6SubnetMask, nil),
		mockEngine.EXPECT().GetIPV6Gateway(deviceName).Return("", errors.New("error")),
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
		mockEngine.EXPECT().GetIPV4GatewayNetmask(macAddress).Return(eniIPV4Gateway, eniIPV4SubnetMask, nil),
		mockEngine.EXPECT().GetIPV6PrefixLength(macAddress).Return(eniIPV6SubnetMask, nil),
		mockEngine.EXPECT().GetIPV6Gateway(deviceName).Return(eniIPV6Gateway, nil),
		mockEngine.EXPECT().SetupContainerNamespace(gomock.Any(), deviceName, macAddress, eniIPV4AddressWithSubnetMask,
			eniIPV6AddressWithSubnetMask, eniIPV4Gateway, eniIPV6Gateway, false, false).Return(errors.New("error")),
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
		mockEngine.EXPECT().GetIPV4GatewayNetmask(macAddress).Return(eniIPV4Gateway, eniIPV4SubnetMask, nil),
		mockEngine.EXPECT().SetupContainerNamespace(gomock.Any(), deviceName, macAddress, eniIPV4AddressWithSubnetMask, "",
			eniIPV4Gateway, "", false, false).Return(errors.New("error")),
	)

	err := add(eniArgsNoIPV6, mockEngine)
	assert.Error(t, err)
}

func TestAddSubnetGatewayInConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	gomock.InOrder(
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().SetupContainerNamespace(gomock.Any(), deviceName, macAddress,
			eniIPV4AddressWithSubnetMask, "",
			eniIPV4Gateway, "", false, false).Return(nil),
	)

	err := add(eniArgsSubnetGateway, mockEngine)
	assert.NoError(t, err)
}

func TestAddNoError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	gomock.InOrder(
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().GetIPV4GatewayNetmask(macAddress).Return(eniIPV4Gateway, eniIPV4SubnetMask, nil),
		mockEngine.EXPECT().GetIPV6PrefixLength(macAddress).Return(eniIPV6SubnetMask, nil),
		mockEngine.EXPECT().GetIPV6Gateway(deviceName).Return(eniIPV6Gateway, nil),
		mockEngine.EXPECT().SetupContainerNamespace(gomock.Any(), deviceName, macAddress, eniIPV4AddressWithSubnetMask,
			eniIPV6AddressWithSubnetMask, eniIPV4Gateway, eniIPV6Gateway, false, false).Return(nil),
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
		mockEngine.EXPECT().GetIPV4GatewayNetmask(macAddress).Return(eniIPV4Gateway, eniIPV4SubnetMask, nil),
		mockEngine.EXPECT().GetIPV6PrefixLength(macAddress).Return(eniIPV6SubnetMask, nil),
		mockEngine.EXPECT().GetIPV6Gateway(deviceName).Return(eniIPV6Gateway, nil),
		mockEngine.EXPECT().SetupContainerNamespace(gomock.Any(), deviceName, macAddress, eniIPV4AddressWithSubnetMask,
			eniIPV6AddressWithSubnetMask, eniIPV4Gateway, eniIPV6Gateway, false, true).Return(nil),
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
		mockEngine.EXPECT().GetIPV4GatewayNetmask(macAddress).Return(eniIPV4Gateway, eniIPV4SubnetMask, nil),
		mockEngine.EXPECT().SetupContainerNamespace(gomock.Any(), deviceName, macAddress, eniIPV4AddressWithSubnetMask, "",
			eniIPV4Gateway, "", false, false).Return(nil),
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
		mockEngine.EXPECT().GetIPV4GatewayNetmask(macAddress).Return(eniIPV4Gateway, eniIPV4SubnetMask, nil),
		mockEngine.EXPECT().GetIPV6PrefixLength(macAddress).Return(eniIPV6SubnetMask, nil),
		mockEngine.EXPECT().GetIPV6Gateway(deviceName).Return(eniIPV6Gateway, nil),
		mockEngine.EXPECT().SetupContainerNamespace(gomock.Any(), deviceName, macAddress, eniIPV4AddressWithSubnetMask,
			eniIPV6AddressWithSubnetMask, eniIPV4Gateway, eniIPV6Gateway, false, false).Return(nil),
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
		mockEngine.EXPECT().GetIPV4GatewayNetmask(macAddress).Return(eniIPV4Gateway, eniIPV4SubnetMask, nil),
		mockEngine.EXPECT().SetupContainerNamespace(gomock.Any(), deviceName, macAddress, eniIPV4AddressWithSubnetMask, "",
			eniIPV4Gateway, "", false, false).Return(nil),
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
