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
	"testing"

	"github.com/aws/amazon-ecs-cni-plugins/plugins/eni/engine/mocks"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

const (
	eniIPV4Address               = "10.11.12.13"
	eniIPV6Address               = "2001:db8::68"
	eniID                        = "eni1"
	deviceName                   = "eth1"
	nsName                       = "ns1"
	macAddressSanitized          = "mac1"
	eniIPV4Gateway               = "10.10.10.10"
	eniIPV6Gateway               = "2001:db9::68"
	eniIPV4SubnetMask            = "20"
	eniIPV6SubnetMask            = "32"
	mac                          = "01:23:45:67:89:ab"
	eniIPV4AddressWithSubnetMask = "10.11.12.13/20"
	eniIPV6AddressWithSubnetMask = "2001:db8::68/32"
)

var eniArgs = &skel.CmdArgs{
	StdinData: []byte(`{"eni":"` + eniID +
		`", "ipv4-address":"` + eniIPV4Address +
		`", "mac":"` + mac +
		`", "ipv6-address":"` + eniIPV6Address +
		`"}`),
	Netns: nsName,
}

var eniArgsNoIPV6 = &skel.CmdArgs{
	StdinData: []byte(`{"eni":"` + eniID +
		`", "ipv4-address":"` + eniIPV4Address +
		`", "mac":"` + mac +
		`"}`),
	Netns: nsName,
}

// TODO: Add integration tests for command.Add commands.Del

func TestAddWithInvalidConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	err := add(&skel.CmdArgs{}, mockEngine)
	assert.Error(t, err)
}

func TestAddIsDHClientInPathFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	mockEngine.EXPECT().IsDHClientInPath().Return(false)

	err := add(eniArgs, mockEngine)
	assert.Error(t, err)
	assert.Equal(t, err, dhclientNotFoundError)
}

func TestAddGetAllMACAddressesFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	gomock.InOrder(
		mockEngine.EXPECT().IsDHClientInPath().Return(true),
		mockEngine.EXPECT().GetAllMACAddresses().Return([]string{}, errors.New("error")),
	)

	err := add(eniArgs, mockEngine)
	assert.Error(t, err)
}

func TestAddGetMACAddressesForENIFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	macAddresses := []string{macAddressSanitized}
	gomock.InOrder(
		mockEngine.EXPECT().IsDHClientInPath().Return(true),
		mockEngine.EXPECT().GetAllMACAddresses().Return(macAddresses, nil),
		mockEngine.EXPECT().GetMACAddressOfENI(macAddresses, eniID).Return("", errors.New("error")),
	)

	err := add(eniArgs, mockEngine)
	assert.Error(t, err)
}

func TestAddDoesMACAddressMapToIPV4AddressFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	macAddress := macAddressSanitized
	macAddresses := []string{macAddress}
	gomock.InOrder(
		mockEngine.EXPECT().IsDHClientInPath().Return(true),
		mockEngine.EXPECT().GetAllMACAddresses().Return(macAddresses, nil),
		mockEngine.EXPECT().GetMACAddressOfENI(macAddresses, eniID).Return(macAddress, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV4Address(macAddress, eniIPV4Address).Return(false, errors.New("error")),
	)

	err := add(eniArgs, mockEngine)
	assert.Error(t, err)
	assert.NotEqual(t, err, unmappedIPV4AddressError)
}

func TestAddDoesMACAddressMapToIPV4AddressReturnsFalse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	macAddress := macAddressSanitized
	macAddresses := []string{macAddress}
	gomock.InOrder(
		mockEngine.EXPECT().IsDHClientInPath().Return(true),
		mockEngine.EXPECT().GetAllMACAddresses().Return(macAddresses, nil),
		mockEngine.EXPECT().GetMACAddressOfENI(macAddresses, eniID).Return(macAddress, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV4Address(macAddress, eniIPV4Address).Return(false, nil),
	)

	err := add(eniArgs, mockEngine)
	assert.Error(t, err)
	assert.Equal(t, err, unmappedIPV4AddressError)
}

func TestAddDoesMACAddressMapToIPV6AddressFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	macAddress := macAddressSanitized
	macAddresses := []string{macAddress}
	gomock.InOrder(
		mockEngine.EXPECT().IsDHClientInPath().Return(true),
		mockEngine.EXPECT().GetAllMACAddresses().Return(macAddresses, nil),
		mockEngine.EXPECT().GetMACAddressOfENI(macAddresses, eniID).Return(macAddress, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV4Address(macAddress, eniIPV4Address).Return(true, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV6Address(macAddress, eniIPV6Address).Return(false, errors.New("error")),
	)

	err := add(eniArgs, mockEngine)
	assert.Error(t, err)
}

func TestAddDoesMACAddressMapToIPV6AddressReturnsFalse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	macAddress := macAddressSanitized
	macAddresses := []string{macAddress}
	gomock.InOrder(
		mockEngine.EXPECT().IsDHClientInPath().Return(true),
		mockEngine.EXPECT().GetAllMACAddresses().Return(macAddresses, nil),
		mockEngine.EXPECT().GetMACAddressOfENI(macAddresses, eniID).Return(macAddress, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV4Address(macAddress, eniIPV4Address).Return(true, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV6Address(macAddress, eniIPV6Address).Return(false, nil),
	)

	err := add(eniArgs, mockEngine)
	assert.Error(t, err)
	assert.Equal(t, err, unmappedIPV6AddressError)
}

func TestAddGetInterfaceDeviceNameFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	macAddress := macAddressSanitized
	macAddresses := []string{macAddress}
	gomock.InOrder(
		mockEngine.EXPECT().IsDHClientInPath().Return(true),
		mockEngine.EXPECT().GetAllMACAddresses().Return(macAddresses, nil),
		mockEngine.EXPECT().GetMACAddressOfENI(macAddresses, eniID).Return(macAddress, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV4Address(macAddress, eniIPV4Address).Return(true, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV6Address(macAddress, eniIPV6Address).Return(true, nil),
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return("", errors.New("error")),
	)

	err := add(eniArgs, mockEngine)
	assert.Error(t, err)
}

func TestAddGetIPV4GatewayNetmaskFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	macAddress := macAddressSanitized
	macAddresses := []string{macAddress}
	gomock.InOrder(
		mockEngine.EXPECT().IsDHClientInPath().Return(true),
		mockEngine.EXPECT().GetAllMACAddresses().Return(macAddresses, nil),
		mockEngine.EXPECT().GetMACAddressOfENI(macAddresses, eniID).Return(macAddress, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV4Address(macAddress, eniIPV4Address).Return(true, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV6Address(macAddress, eniIPV6Address).Return(true, nil),
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
	macAddress := macAddressSanitized
	macAddresses := []string{macAddress}
	gomock.InOrder(
		mockEngine.EXPECT().IsDHClientInPath().Return(true),
		mockEngine.EXPECT().GetAllMACAddresses().Return(macAddresses, nil),
		mockEngine.EXPECT().GetMACAddressOfENI(macAddresses, eniID).Return(macAddress, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV4Address(macAddress, eniIPV4Address).Return(true, nil),
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
	macAddress := macAddressSanitized
	macAddresses := []string{macAddress}
	gomock.InOrder(
		mockEngine.EXPECT().IsDHClientInPath().Return(true),
		mockEngine.EXPECT().GetAllMACAddresses().Return(macAddresses, nil),
		mockEngine.EXPECT().GetMACAddressOfENI(macAddresses, eniID).Return(macAddress, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV4Address(macAddress, eniIPV4Address).Return(true, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV6Address(macAddress, eniIPV6Address).Return(true, nil),
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().GetIPV4GatewayNetmask(macAddress).Return(eniIPV4Gateway, eniIPV4SubnetMask, nil),
		mockEngine.EXPECT().GetIPV6Netmask(macAddress).Return("", errors.New("error")),
	)

	err := add(eniArgs, mockEngine)
	assert.Error(t, err)
}

func TestAddGetIPV6GatewayFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	macAddress := macAddressSanitized
	macAddresses := []string{macAddress}
	gomock.InOrder(
		mockEngine.EXPECT().IsDHClientInPath().Return(true),
		mockEngine.EXPECT().GetAllMACAddresses().Return(macAddresses, nil),
		mockEngine.EXPECT().GetMACAddressOfENI(macAddresses, eniID).Return(macAddress, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV4Address(macAddress, eniIPV4Address).Return(true, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV6Address(macAddress, eniIPV6Address).Return(true, nil),
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().GetIPV4GatewayNetmask(macAddress).Return(eniIPV4Gateway, eniIPV4SubnetMask, nil),
		mockEngine.EXPECT().GetIPV6Netmask(macAddress).Return(eniIPV6SubnetMask, nil),
		mockEngine.EXPECT().GetIPV6Gateway(deviceName).Return("", errors.New("error")),
	)

	err := add(eniArgs, mockEngine)
	assert.Error(t, err)
}

func TestAddSetupContainerNamespaceFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	macAddress := macAddressSanitized
	macAddresses := []string{macAddress}
	gomock.InOrder(
		mockEngine.EXPECT().IsDHClientInPath().Return(true),
		mockEngine.EXPECT().GetAllMACAddresses().Return(macAddresses, nil),
		mockEngine.EXPECT().GetMACAddressOfENI(macAddresses, eniID).Return(macAddress, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV4Address(macAddress, eniIPV4Address).Return(true, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV6Address(macAddress, eniIPV6Address).Return(true, nil),
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().GetIPV4GatewayNetmask(macAddress).Return(eniIPV4Gateway, eniIPV4SubnetMask, nil),
		mockEngine.EXPECT().GetIPV6Netmask(macAddress).Return(eniIPV6SubnetMask, nil),
		mockEngine.EXPECT().GetIPV6Gateway(deviceName).Return(eniIPV6Gateway, nil),
		mockEngine.EXPECT().SetupContainerNamespace(nsName, deviceName, eniIPV4AddressWithSubnetMask, eniIPV6AddressWithSubnetMask).Return(errors.New("error")),
	)

	err := add(eniArgs, mockEngine)
	assert.Error(t, err)
}

func TestAddSetupContainerNamespaceFailsNoIPV6(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	macAddress := macAddressSanitized
	macAddresses := []string{macAddress}
	gomock.InOrder(
		mockEngine.EXPECT().IsDHClientInPath().Return(true),
		mockEngine.EXPECT().GetAllMACAddresses().Return(macAddresses, nil),
		mockEngine.EXPECT().GetMACAddressOfENI(macAddresses, eniID).Return(macAddress, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV4Address(macAddress, eniIPV4Address).Return(true, nil),
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().GetIPV4GatewayNetmask(macAddress).Return(eniIPV4Gateway, eniIPV4SubnetMask, nil),
		mockEngine.EXPECT().SetupContainerNamespace(nsName, deviceName, eniIPV4AddressWithSubnetMask, "").Return(errors.New("error")),
	)

	err := add(eniArgsNoIPV6, mockEngine)
	assert.Error(t, err)
}

func TestAddNoError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	macAddress := macAddressSanitized
	macAddresses := []string{macAddress}
	gomock.InOrder(
		mockEngine.EXPECT().IsDHClientInPath().Return(true),
		mockEngine.EXPECT().GetAllMACAddresses().Return(macAddresses, nil),
		mockEngine.EXPECT().GetMACAddressOfENI(macAddresses, eniID).Return(macAddress, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV4Address(macAddress, eniIPV4Address).Return(true, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV6Address(macAddress, eniIPV6Address).Return(true, nil),
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().GetIPV4GatewayNetmask(macAddress).Return(eniIPV4Gateway, eniIPV4SubnetMask, nil),
		mockEngine.EXPECT().GetIPV6Netmask(macAddress).Return(eniIPV6SubnetMask, nil),
		mockEngine.EXPECT().GetIPV6Gateway(deviceName).Return(eniIPV6Gateway, nil),
		mockEngine.EXPECT().SetupContainerNamespace(nsName, deviceName, eniIPV4AddressWithSubnetMask, eniIPV6AddressWithSubnetMask).Return(nil),
	)

	err := add(eniArgs, mockEngine)
	assert.NoError(t, err)
}

func TestAddNoErrorWhenIPV6AddressNotSpecifiedInConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	macAddress := macAddressSanitized
	macAddresses := []string{macAddress}
	gomock.InOrder(
		mockEngine.EXPECT().IsDHClientInPath().Return(true),
		mockEngine.EXPECT().GetAllMACAddresses().Return(macAddresses, nil),
		mockEngine.EXPECT().GetMACAddressOfENI(macAddresses, eniID).Return(macAddress, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV4Address(macAddress, eniIPV4Address).Return(true, nil),
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().GetIPV4GatewayNetmask(macAddress).Return(eniIPV4Gateway, eniIPV4SubnetMask, nil),
		mockEngine.EXPECT().SetupContainerNamespace(nsName, deviceName, eniIPV4AddressWithSubnetMask, "").Return(nil),
	)

	err := add(eniArgsNoIPV6, mockEngine)
	assert.NoError(t, err)
}

func TestDelWithInvalidConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	err := del(&skel.CmdArgs{}, mockEngine)
	assert.Error(t, err)
}

func TestDelFailsWhenTearDownContainerNamespaceFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	mockEngine.EXPECT().TeardownContainerNamespace(nsName, mac, true).Return(errors.New("error"))
	err := del(eniArgs, mockEngine)
	assert.Error(t, err)
}

func TestDel(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	mockEngine.EXPECT().TeardownContainerNamespace(nsName, mac, true).Return(nil)
	err := del(eniArgs, mockEngine)
	assert.NoError(t, err)
}

func TestDelNoIPV6(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	mockEngine.EXPECT().TeardownContainerNamespace(nsName, mac, false).Return(nil)
	err := del(eniArgsNoIPV6, mockEngine)
	assert.NoError(t, err)
}
