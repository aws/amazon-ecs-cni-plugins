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

package engine

import (
	"errors"
	"os"
	"testing"

	"github.com/aws/amazon-ecs-cni-plugins/pkg/cninswrapper/mocks"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/cninswrapper/mocks_netns"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/ec2metadata/mocks"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/ioutilwrapper/mocks_fileinfo"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/ioutilwrapper/mocks_ioutilwrapper"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/netlinkwrapper/mocks"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/netlinkwrapper/mocks_link"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

func setup(t *testing.T) (*gomock.Controller, *mock_ec2metadata.MockEC2Metadata, *mock_ioutilwrapper.MockIOUtil, *mock_cninswrapper.MockNS, *mock_netlinkwrapper.MockNetLink) {
	ctrl := gomock.NewController(t)
	return ctrl, mock_ec2metadata.NewMockEC2Metadata(ctrl), mock_ioutilwrapper.NewMockIOUtil(ctrl), mock_cninswrapper.NewMockNS(ctrl), mock_netlinkwrapper.NewMockNetLink(ctrl)
}

func TestGetAllMACAddressesReturnsErrorOnGetMetadataError(t *testing.T) {
	ctrl, mockMetadata, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata}

	_, err := engine.GetAllMACAddresses()
	assert.Error(t, err)
}

func TestGetAllMACAddresses(t *testing.T) {
	ctrl, mockMetadata, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath).Return("a\nb", nil)
	engine := &engine{metadata: mockMetadata}

	macs, err := engine.GetAllMACAddresses()
	assert.NoError(t, err)
	assert.NotEmpty(t, macs)
	assert.Len(t, macs, 2)
}

func TestGetMACAddressOfENIReturnsErrorOnGetMetadataError(t *testing.T) {
	ctrl, mockMetadata, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+"mac1/"+metadataNetworkInterfaceIDPathSuffix).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata}

	_, err := engine.GetMACAddressOfENI([]string{"mac1/"}, "eni1")
	assert.Error(t, err)
}

func TestGetMACAddressOfENIReturnsErrorWhenNotFound(t *testing.T) {
	ctrl, mockMetadata, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+"mac1/"+metadataNetworkInterfaceIDPathSuffix).Return("eni1", nil)
	engine := &engine{metadata: mockMetadata}

	_, err := engine.GetMACAddressOfENI([]string{"mac1/"}, "eni2")
	assert.Error(t, err)
}

func TestGetMACAddressOfENI(t *testing.T) {
	ctrl, mockMetadata, _, _, _ := setup(t)
	defer ctrl.Finish()

	gomock.InOrder(
		mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+"mac1/"+metadataNetworkInterfaceIDPathSuffix).Return("eni1", nil),
		mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+"mac2/"+metadataNetworkInterfaceIDPathSuffix).Return("eni2", nil),
	)
	engine := &engine{metadata: mockMetadata}

	addr, err := engine.GetMACAddressOfENI([]string{"mac1/", "mac2/"}, "eni2")
	assert.NoError(t, err)
	assert.Equal(t, addr, "mac2")
}

func TestGetInterfaceDeviceNameReturnsErrorOnReadDirError(t *testing.T) {
	ctrl, _, mockIOUtil, _, _ := setup(t)
	defer ctrl.Finish()

	mockIOUtil.EXPECT().ReadDir(sysfsPathForNetworkDevices).Return(nil, errors.New("error"))
	engine := &engine{ioutil: mockIOUtil}

	_, err := engine.GetInterfaceDeviceName("mac1")
	assert.Error(t, err)
}

func TestGetInterfaceDeviceNameReturnsErrorOnReadFileError(t *testing.T) {
	ctrl, _, mockIOUtil, _, _ := setup(t)
	defer ctrl.Finish()

	mockFileInfo := mock_os.NewMockFileInfo(ctrl)
	gomock.InOrder(
		mockIOUtil.EXPECT().ReadDir(sysfsPathForNetworkDevices).Return([]os.FileInfo{mockFileInfo}, nil),
		mockFileInfo.EXPECT().Name().Return("eth1"),
		mockIOUtil.EXPECT().ReadFile(sysfsPathForNetworkDevices+"eth1"+sysfsPathForNetworkDeviceAddressSuffix).Return(nil, errors.New("error")),
		mockFileInfo.EXPECT().Name().Return("eth1"),
	)
	engine := &engine{ioutil: mockIOUtil}

	_, err := engine.GetInterfaceDeviceName("mac1")
	assert.Error(t, err)
}

func TestGetInterfaceDeviceNameReturnsErrorWhenDeviceNotFound(t *testing.T) {
	ctrl, _, mockIOUtil, _, _ := setup(t)
	defer ctrl.Finish()

	mockFileInfo := mock_os.NewMockFileInfo(ctrl)
	gomock.InOrder(
		mockIOUtil.EXPECT().ReadDir(sysfsPathForNetworkDevices).Return([]os.FileInfo{mockFileInfo}, nil),
		mockFileInfo.EXPECT().Name().Return("eth1"),
		mockIOUtil.EXPECT().ReadFile(
			sysfsPathForNetworkDevices+"eth1"+sysfsPathForNetworkDeviceAddressSuffix).Return([]byte("mac2"), nil),
	)
	engine := &engine{ioutil: mockIOUtil}

	_, err := engine.GetInterfaceDeviceName("mac1")
	assert.Error(t, err)
}

func TestGetInterfaceDeviceNameReturnsDeviceWhenFound(t *testing.T) {
	ctrl, _, mockIOUtil, _, _ := setup(t)
	defer ctrl.Finish()

	mockFileInfoEth1 := mock_os.NewMockFileInfo(ctrl)
	mockFileInfoEth2 := mock_os.NewMockFileInfo(ctrl)
	gomock.InOrder(
		mockIOUtil.EXPECT().ReadDir(sysfsPathForNetworkDevices).Return([]os.FileInfo{mockFileInfoEth1, mockFileInfoEth2}, nil),
		mockFileInfoEth1.EXPECT().Name().Return("eth1"),
		mockIOUtil.EXPECT().ReadFile(
			sysfsPathForNetworkDevices+"eth1"+sysfsPathForNetworkDeviceAddressSuffix).Return([]byte("mac1"), nil),
		mockFileInfoEth2.EXPECT().Name().Return("eth2"),
		mockIOUtil.EXPECT().ReadFile(
			sysfsPathForNetworkDevices+"eth2"+sysfsPathForNetworkDeviceAddressSuffix).Return([]byte("mac2"), nil),
		mockFileInfoEth2.EXPECT().Name().Return("eth2"),
	)
	engine := &engine{ioutil: mockIOUtil}

	deviceName, err := engine.GetInterfaceDeviceName("mac2")
	assert.NoError(t, err)
	assert.Equal(t, deviceName, "eth2")
}

func TestGetIPV4GatewayNetMaskReturnsErrorOnGetMetadataError(t *testing.T) {
	ctrl, mockMetadata, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+"mac1"+metadataNetworkInterfaceIPV4SubnetCIDRPathSuffix).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata}

	_, _, err := engine.GetIPV4GatewayNetmask("mac1")
	assert.Error(t, err)
}

func TestGetIPV4GatewayNetMaskReturnsErrorWhenUnableToParseCIDRNetmaskResponse(t *testing.T) {
	ctrl, mockMetadata, _, _, _ := setup(t)
	defer ctrl.Finish()

	engine := &engine{metadata: mockMetadata}
	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+"mac1"+metadataNetworkInterfaceIPV4SubnetCIDRPathSuffix).Return("1.1.1.1", nil)
	_, _, err := engine.GetIPV4GatewayNetmask("mac1")
	assert.Error(t, err)
	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+"mac1"+metadataNetworkInterfaceIPV4SubnetCIDRPathSuffix).Return("1.1.1.1/", nil)
	_, _, err = engine.GetIPV4GatewayNetmask("mac1")
	assert.Error(t, err)
}

func TestGetIPV4GatewayNetMaskReturnsErrorWhenUnableToParseCIDRBlockInResponse(t *testing.T) {
	ctrl, mockMetadata, _, _, _ := setup(t)
	defer ctrl.Finish()

	engine := &engine{metadata: mockMetadata}
	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+"mac1"+metadataNetworkInterfaceIPV4SubnetCIDRPathSuffix).Return("1.1.1./1", nil)
	_, _, err := engine.GetIPV4GatewayNetmask("mac1")
	assert.Error(t, err)

	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+"mac1"+metadataNetworkInterfaceIPV4SubnetCIDRPathSuffix).Return("1.1.1/1", nil)
	_, _, err = engine.GetIPV4GatewayNetmask("mac1")
	assert.Error(t, err)
}

func TestGetIPV4GatewayNetMask(t *testing.T) {
	ctrl, mockMetadata, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+"mac1"+metadataNetworkInterfaceIPV4SubnetCIDRPathSuffix).Return("172.31.32.0/20", nil)
	engine := &engine{metadata: mockMetadata}

	gateway, netmask, err := engine.GetIPV4GatewayNetmask("mac1")
	assert.NoError(t, err)
	assert.Equal(t, "172.31.32.1", gateway)
	assert.Equal(t, "20", netmask)
}

func TestIsValidGetIPV4AddressReturnsErrorOnGetMetadataError(t *testing.T) {
	ctrl, mockMetadata, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+"mac1"+metadataNetworkInterfaceIPV4AddressesSuffix).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata}

	_, err := engine.DoesMACAddressMapToIPV4Address("mac1", "10.11.12.13")
	assert.Error(t, err)
}

func TestDoesMACAddressMapToIPV4AddressReturnsFalseWhenNotFound(t *testing.T) {
	ctrl, mockMetadata, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+"mac1"+metadataNetworkInterfaceIPV4AddressesSuffix).Return("172.31.32.3", nil)
	engine := &engine{metadata: mockMetadata}

	ok, err := engine.DoesMACAddressMapToIPV4Address("mac1", "10.11.12.13")
	assert.NoError(t, err)
	assert.False(t, ok)
}

func TestDoesMACAddressMapToIPV4AddressReturnsTrueWhenFound(t *testing.T) {
	ctrl, mockMetadata, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+"mac1"+metadataNetworkInterfaceIPV4AddressesSuffix).Return("10.11.12.13", nil)
	engine := &engine{metadata: mockMetadata}

	ok, err := engine.DoesMACAddressMapToIPV4Address("mac1", "10.11.12.13")
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestSetupContainerNamespaceFailsOnLinkByNameError(t *testing.T) {
	ctrl, _, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkByName("eth1").Return(nil, errors.New("error"))
	engine := &engine{netLink: mockNetLink}
	err := engine.SetupContainerNamespace("ns1", "eth1", "10.10.10.10", "20")
	assert.Error(t, err)
}

func TestSetupContainerNamespaceFailsOnGetNSError(t *testing.T) {
	ctrl, _, _, mockNS, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockLink := mock_netlink.NewMockLink(ctrl)
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName("eth1").Return(mockLink, nil),
		mockNS.EXPECT().GetNS("ns1").Return(nil, errors.New("error")),
	)
	engine := &engine{ns: mockNS, netLink: mockNetLink}
	err := engine.SetupContainerNamespace("ns1", "eth1", "10.10.10.10", "20")
	assert.Error(t, err)
}

func TestSetupContainerNamespaceFailsOnLinksetNsFdError(t *testing.T) {
	ctrl, _, _, mockNS, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockENILink := mock_netlink.NewMockLink(ctrl)
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	var fd uintptr
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName("eth1").Return(mockENILink, nil),
		mockNS.EXPECT().GetNS("ns1").Return(mockNetNS, nil),
		mockNetNS.EXPECT().Fd().Return(fd),
		mockNetLink.EXPECT().LinkSetNsFd(mockENILink, int(fd)).Return(errors.New("error")),
	)
	engine := &engine{ns: mockNS, netLink: mockNetLink}
	err := engine.SetupContainerNamespace("ns1", "eth1", "10.10.10.10", "20")
	assert.Error(t, err)
}

func TestSetupContainerNamespaceFailsOnWithNetNSPathError(t *testing.T) {
	ctrl, _, _, mockNS, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockENILink := mock_netlink.NewMockLink(ctrl)
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	var fd uintptr
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName("eth1").Return(mockENILink, nil),
		mockNS.EXPECT().GetNS("ns1").Return(mockNetNS, nil),
		mockNetNS.EXPECT().Fd().Return(fd),
		mockNetLink.EXPECT().LinkSetNsFd(mockENILink, int(fd)).Return(nil),
		mockNS.EXPECT().WithNetNSPath("ns1", gomock.Any()).Return(errors.New("error")),
	)
	engine := &engine{ns: mockNS, netLink: mockNetLink}
	err := engine.SetupContainerNamespace("ns1", "eth1", "10.10.10.10", "20")
	assert.Error(t, err)
}

func TestSetupContainerNamespace(t *testing.T) {
	ctrl, _, _, mockNS, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockENILink := mock_netlink.NewMockLink(ctrl)
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	var fd uintptr
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName("eth1").Return(mockENILink, nil),
		mockNS.EXPECT().GetNS("ns1").Return(mockNetNS, nil),
		mockNetNS.EXPECT().Fd().Return(fd),
		mockNetLink.EXPECT().LinkSetNsFd(mockENILink, int(fd)).Return(nil),
		mockNS.EXPECT().WithNetNSPath("ns1", gomock.Any()).Return(nil),
	)
	engine := &engine{ns: mockNS, netLink: mockNetLink}
	err := engine.SetupContainerNamespace("ns1", "eth1", "10.10.10.10", "20")
	assert.NoError(t, err)
}

func TestNSClosureRunFailsOnLinkByNameError(t *testing.T) {
	ctrl, _, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockNetLink.EXPECT().LinkByName("eth1").Return(nil, errors.New("error"))
	closure := &nsClosure{
		netLink:    mockNetLink,
		deviceName: "eth1",
	}
	err := closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestNSClosureRunFailsOnParseAddrError(t *testing.T) {
	ctrl, _, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName("eth1").Return(mockENILink, nil),
		mockNetLink.EXPECT().ParseAddr("10.10.10.10/20").Return(nil, errors.New("error")),
	)
	closure := &nsClosure{
		netLink:     mockNetLink,
		deviceName:  "eth1",
		ipv4Address: "10.10.10.10",
		netmask:     "20",
	}
	err := closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestNSClosureRunFailsOnAddrAddError(t *testing.T) {
	ctrl, _, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	netlinkAddress := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName("eth1").Return(mockENILink, nil),
		mockNetLink.EXPECT().ParseAddr("10.10.10.10/20").Return(netlinkAddress, nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, netlinkAddress).Return(errors.New("error")),
	)
	closure := &nsClosure{
		netLink:     mockNetLink,
		deviceName:  "eth1",
		ipv4Address: "10.10.10.10",
		netmask:     "20",
	}
	err := closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestNSClosureRunFailsOnLinkSetupError(t *testing.T) {
	ctrl, _, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	netlinkAddress := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName("eth1").Return(mockENILink, nil),
		mockNetLink.EXPECT().ParseAddr("10.10.10.10/20").Return(netlinkAddress, nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, netlinkAddress).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(mockENILink).Return(errors.New("error")),
	)
	closure := &nsClosure{
		netLink:     mockNetLink,
		deviceName:  "eth1",
		ipv4Address: "10.10.10.10",
		netmask:     "20",
	}
	err := closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestNSClosureRun(t *testing.T) {
	ctrl, _, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	netlinkAddress := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName("eth1").Return(mockENILink, nil),
		mockNetLink.EXPECT().ParseAddr("10.10.10.10/20").Return(netlinkAddress, nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, netlinkAddress).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(mockENILink).Return(nil),
	)
	closure := &nsClosure{
		netLink:     mockNetLink,
		deviceName:  "eth1",
		ipv4Address: "10.10.10.10",
		netmask:     "20",
	}
	err := closure.run(mockNetNS)
	assert.NoError(t, err)
}
