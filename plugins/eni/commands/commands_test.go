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
	eniIPV4Address      = "10.11.12.13"
	eniID               = "eni1"
	deviceName          = "eth1"
	nsName              = "ns1"
	macAddressSanitized = "mac1"
	eniIPV4Gateway      = "10.10.10.10"
	eniSubnetMask       = "20"
)

var eniArgs = &skel.CmdArgs{
	StdinData: []byte(`{"eni":"` + eniID + `", "ipv4-address":"` + eniIPV4Address + `"}`),
	Netns:     nsName,
}

func TestAddWithInvalidConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	err := add(&skel.CmdArgs{}, mockEngine)
	assert.Error(t, err)
}

func TestAddGetAllMACAddressesFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	mockEngine.EXPECT().GetAllMACAddresses().Return([]string{}, errors.New("error"))

	err := add(eniArgs, mockEngine)
	assert.Error(t, err)
}

func TestAddGetMACAddressesForENIFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	macAddresses := []string{macAddressSanitized}
	gomock.InOrder(
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
		mockEngine.EXPECT().GetAllMACAddresses().Return(macAddresses, nil),
		mockEngine.EXPECT().GetMACAddressOfENI(macAddresses, eniID).Return(macAddress, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV4Address(macAddress, eniIPV4Address).Return(false, errors.New("error")),
	)

	err := add(eniArgs, mockEngine)
	assert.Error(t, err)
}

func TestAddDoesMACAddressMapToIPV4AddressReturnsFalse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	macAddress := macAddressSanitized
	macAddresses := []string{macAddress}
	gomock.InOrder(
		mockEngine.EXPECT().GetAllMACAddresses().Return(macAddresses, nil),
		mockEngine.EXPECT().GetMACAddressOfENI(macAddresses, eniID).Return(macAddress, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV4Address(macAddress, eniIPV4Address).Return(false, nil),
	)

	err := add(eniArgs, mockEngine)
	assert.Error(t, err)
}

func TestAddGetInterfaceDeviceNameFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	macAddress := macAddressSanitized
	macAddresses := []string{macAddress}
	gomock.InOrder(
		mockEngine.EXPECT().GetAllMACAddresses().Return(macAddresses, nil),
		mockEngine.EXPECT().GetMACAddressOfENI(macAddresses, eniID).Return(macAddress, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV4Address(macAddress, eniIPV4Address).Return(true, nil),
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
		mockEngine.EXPECT().GetAllMACAddresses().Return(macAddresses, nil),
		mockEngine.EXPECT().GetMACAddressOfENI(macAddresses, eniID).Return(macAddress, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV4Address(macAddress, eniIPV4Address).Return(true, nil),
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().GetIPV4GatewayNetmask(macAddress).Return("", "", errors.New("error")),
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
		mockEngine.EXPECT().GetAllMACAddresses().Return(macAddresses, nil),
		mockEngine.EXPECT().GetMACAddressOfENI(macAddresses, eniID).Return(macAddress, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV4Address(macAddress, eniIPV4Address).Return(true, nil),
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().GetIPV4GatewayNetmask(macAddress).Return(eniIPV4Gateway, eniSubnetMask, nil),
		mockEngine.EXPECT().SetupContainerNamespace(nsName, deviceName, eniIPV4Address, eniSubnetMask).Return(errors.New("error")),
	)

	err := add(eniArgs, mockEngine)
	assert.Error(t, err)
}

func TestAddNoError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	macAddress := macAddressSanitized
	macAddresses := []string{macAddress}
	gomock.InOrder(
		mockEngine.EXPECT().GetAllMACAddresses().Return(macAddresses, nil),
		mockEngine.EXPECT().GetMACAddressOfENI(macAddresses, eniID).Return(macAddress, nil),
		mockEngine.EXPECT().DoesMACAddressMapToIPV4Address(macAddress, eniIPV4Address).Return(true, nil),
		mockEngine.EXPECT().GetInterfaceDeviceName(macAddress).Return(deviceName, nil),
		mockEngine.EXPECT().GetIPV4GatewayNetmask(macAddress).Return(eniIPV4Gateway, eniSubnetMask, nil),
		mockEngine.EXPECT().SetupContainerNamespace(nsName, deviceName, eniIPV4Address, eniSubnetMask).Return(nil),
	)

	err := add(eniArgs, mockEngine)
	assert.NoError(t, err)
}
