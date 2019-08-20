// +build !integration,!e2e

// Copyright 2017-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/containernetworking/cni/pkg/skel"

	mock_cninswrapper "github.com/aws/amazon-ecs-cni-plugins/pkg/cninswrapper/mocks"
	mock_ns "github.com/aws/amazon-ecs-cni-plugins/pkg/cninswrapper/mocks_netns"
	mock_ec2metadata "github.com/aws/amazon-ecs-cni-plugins/pkg/ec2metadata/mocks"
	mock_netlinkwrapper "github.com/aws/amazon-ecs-cni-plugins/pkg/netlinkwrapper/mocks"
	mock_netlink "github.com/aws/amazon-ecs-cni-plugins/pkg/netlinkwrapper/mocks_link"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/utils"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

const (
	deviceName                = "eth1"
	firstENIID                = "eni1"
	secondENIID               = "eni2"
	firstMACAddress           = "mac1/"
	firstMACAddressSanitized  = "mac1"
	secondMACAddress          = "mac2/"
	secondMACAddressSanitized = "mac2"
	eniIPV4Address            = "10.11.12.13"
	eniIPV6Address            = "2001:db8::68"
	eniIPV4Gateway            = "10.10.10.10"
	eniIPV6Gateway            = "2001:db9::68"
	eniSubnetMask             = "20"
	eniIPV4CIDRBlock          = "10.10.10.10/20"
	eniIPV6CIDRBlock          = "2001:db8::68/32"
	eniMACAddress             = "01:23:45:67:89:ab"
	unknownMACAddress         = "01:23:45:67:89:cd"
	loMACAddress              = "00:00:00:00:00:00"
	invalidMACAddress         = "01:23:45:67:89"
)

func setup(t *testing.T) (*gomock.Controller,
	*mock_ec2metadata.MockEC2Metadata,
	*mock_cninswrapper.MockNS,
	*mock_netlinkwrapper.MockNetLink) {
	ctrl := gomock.NewController(t)
	return ctrl,
		mock_ec2metadata.NewMockEC2Metadata(ctrl),
		mock_cninswrapper.NewMockNS(ctrl),
		mock_netlinkwrapper.NewMockNetLink(ctrl)
}

func TestCreate(t *testing.T) {
	ctrl, mockMetadata, mockNS, mockNetLink := setup(t)
	defer ctrl.Finish()

	engine := create(mockMetadata, mockNetLink, mockNS)
	assert.NotNil(t, engine)
}

func TestGetAllMACAddressesReturnsErrorOnGetMetadataError(t *testing.T) {
	ctrl, mockMetadata, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata}

	_, err := engine.GetAllMACAddresses()
	assert.Error(t, err)
}

func TestGetAllMACAddresses(t *testing.T) {
	ctrl, mockMetadata, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath).Return("a\nb", nil)
	engine := &engine{metadata: mockMetadata}

	macs, err := engine.GetAllMACAddresses()
	assert.NoError(t, err)
	assert.NotEmpty(t, macs)
	assert.Len(t, macs, 2)
}

func TestGetMACAddressOfENIReturnsErrorOnGetMetadataError(t *testing.T) {
	ctrl, mockMetadata, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddress+metadataNetworkInterfaceIDPathSuffix).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata}

	_, err := engine.GetMACAddressOfENI([]string{firstMACAddress}, firstENIID)
	assert.Error(t, err)
	_, ok := err.(*UnmappedMACAddressError)
	assert.True(t, ok)
}

func TestGetMACAddressOfENIReturnsErrorWhenNotFound(t *testing.T) {
	ctrl, mockMetadata, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddress+metadataNetworkInterfaceIDPathSuffix).Return(firstENIID, nil)
	engine := &engine{metadata: mockMetadata}

	_, err := engine.GetMACAddressOfENI([]string{firstMACAddress}, secondENIID)
	assert.Error(t, err)
	_, ok := err.(*UnmappedMACAddressError)
	assert.True(t, ok)
}

func TestGetMACAddressOfENI(t *testing.T) {
	ctrl, mockMetadata, _, _ := setup(t)
	defer ctrl.Finish()

	gomock.InOrder(
		mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddress+metadataNetworkInterfaceIDPathSuffix).Return(firstENIID, nil),
		mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+secondMACAddress+metadataNetworkInterfaceIDPathSuffix).Return(secondENIID, nil),
	)
	engine := &engine{metadata: mockMetadata}

	addr, err := engine.GetMACAddressOfENI([]string{firstMACAddress, secondMACAddress}, secondENIID)
	assert.NoError(t, err)
	assert.Equal(t, addr, secondMACAddressSanitized)
}

func TestGetInterfaceDeviceNameReturnsErrorOnInvalidMACAddress(t *testing.T) {
	ctrl, _, _, _ := setup(t)
	defer ctrl.Finish()

	engine := &engine{}

	_, err := engine.GetInterfaceDeviceName("")
	assert.Error(t, err)
}

func TestGetInterfaceDeviceNameReturnsErrorOnLinkListErrort(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkList().Return(nil, errors.New("error"))
	engine := &engine{netLink: mockNetLink}

	_, err := engine.GetInterfaceDeviceName(eniMACAddress)
	assert.Error(t, err)
}

func TestGetInterfaceDeviceNameReturnsErrorWhenDeviceNotFound(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	lo := mock_netlink.NewMockLink(ctrl)
	eth1 := mock_netlink.NewMockLink(ctrl)

	loAddress, err := net.ParseMAC(loMACAddress)
	assert.NoError(t, err)
	eth1Address, err := net.ParseMAC(eniMACAddress)
	assert.NoError(t, err)

	gomock.InOrder(
		mockNetLink.EXPECT().LinkList().Return([]netlink.Link{lo, eth1}, nil),
		lo.EXPECT().Attrs().Return(&netlink.LinkAttrs{HardwareAddr: loAddress}),
		eth1.EXPECT().Attrs().Return(&netlink.LinkAttrs{HardwareAddr: eth1Address}),
	)

	engine := &engine{netLink: mockNetLink}
	_, err = engine.GetInterfaceDeviceName(unknownMACAddress)
	assert.Error(t, err)
}

func TestGetInterfaceDeviceNameReturnsDeviceWhenFound(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	lo := mock_netlink.NewMockLink(ctrl)
	eth1 := mock_netlink.NewMockLink(ctrl)

	loAddress, err := net.ParseMAC(loMACAddress)
	assert.NoError(t, err)
	eth1Address, err := net.ParseMAC(eniMACAddress)
	assert.NoError(t, err)

	gomock.InOrder(
		mockNetLink.EXPECT().LinkList().Return([]netlink.Link{lo, eth1}, nil),
		lo.EXPECT().Attrs().Return(&netlink.LinkAttrs{HardwareAddr: loAddress}),
		eth1.EXPECT().Attrs().Return(&netlink.LinkAttrs{HardwareAddr: eth1Address}),
		eth1.EXPECT().Attrs().Return(&netlink.LinkAttrs{
			HardwareAddr: eth1Address,
			Name:         deviceName,
		}),
	)

	engine := &engine{netLink: mockNetLink}
	eniDeviceName, err := engine.GetInterfaceDeviceName(eniMACAddress)
	assert.NoError(t, err)
	assert.Equal(t, eniDeviceName, deviceName)
}

func TestGetIPV4GatewayNetMaskReturnsErrorOnGetMetadataError(t *testing.T) {
	ctrl, mockMetadata, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV4CIDRPathSuffix).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata}

	_, _, err := engine.GetIPV4GatewayNetmask(firstMACAddressSanitized)
	assert.Error(t, err)
	_, ok := err.(*utils.ParseIPV4GatewayNetmaskError)
	assert.False(t, ok)
}

func TestGetIPV4GatewayNetMaskReturnsErrorWhenUnableToParseCIDRNetmaskResponse(t *testing.T) {
	ctrl, mockMetadata, _, _ := setup(t)
	defer ctrl.Finish()

	engine := &engine{metadata: mockMetadata}
	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV4CIDRPathSuffix).Return("1.1.1.1", nil)
	_, _, err := engine.GetIPV4GatewayNetmask(firstMACAddressSanitized)
	assert.Error(t, err)
	_, ok := err.(*utils.ParseIPV4GatewayNetmaskError)
	assert.False(t, ok)
}

func TestGetIPV4GatewayNetMaskWhenUnableToParseIPV6CIDRNetmaskResponse(t *testing.T) {
	ctrl, mockMetadata, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV4CIDRPathSuffix).Return("2001:db8::/32", nil)
	engine := &engine{metadata: mockMetadata}

	_, _, err := engine.GetIPV4GatewayNetmask(firstMACAddressSanitized)
	assert.Error(t, err)
	_, ok := err.(*utils.ParseIPV4GatewayNetmaskError)
	assert.True(t, ok)
}

func TestGetIPV4GatewayNetMask(t *testing.T) {
	ctrl, mockMetadata, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV4CIDRPathSuffix).Return("172.31.32.0/20", nil)
	engine := &engine{metadata: mockMetadata}

	gateway, netmask, err := engine.GetIPV4GatewayNetmask(firstMACAddressSanitized)
	assert.NoError(t, err)
	assert.Equal(t, "172.31.32.1", gateway)
	assert.Equal(t, "20", netmask)
}

func TestGetIPV6NetmaskInternalReturnsErrorOnMalformedCIDR(t *testing.T) {
	_, err := getIPV6PrefixLength("2001:db8::")
	assert.Error(t, err)
}

func TestGetIPV6NetmaskInternalReturnsErrorOnMalformedNetmaskInCIDR(t *testing.T) {
	_, err := getIPV6PrefixLength("2001:db8::/")
	assert.Error(t, err)
}

func TestGetIPV6NetmaskInternalReturnsErrorOnMalformedCIDRBlockInCIDR(t *testing.T) {
	_, err := getIPV6PrefixLength("2001:::/32")
	assert.Error(t, err)
}

func TestGetIPV6NetMaskInternal(t *testing.T) {
	netmask, err := getIPV6PrefixLength("2001:db8::/32")
	assert.NoError(t, err)
	assert.Equal(t, netmask, "32")
}

func TestGetIPV6NetMaskReturnsErrorOnGetMetadataError(t *testing.T) {
	ctrl, mockMetadata, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV6CIDRPathSuffix).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata}

	_, err := engine.GetIPV6PrefixLength(firstMACAddressSanitized)
	assert.Error(t, err)
}

func TestGetIPV6NetMaskReturnsErrorWhenUnableToParseCIDRNetmaskResponse(t *testing.T) {
	ctrl, mockMetadata, _, _ := setup(t)
	defer ctrl.Finish()

	engine := &engine{metadata: mockMetadata}
	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV6CIDRPathSuffix).Return("2001:db8::", nil)
	_, err := engine.GetIPV6PrefixLength(firstMACAddressSanitized)
	assert.Error(t, err)
}

func TestGetIPV6NetMask(t *testing.T) {
	ctrl, mockMetadata, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV6CIDRPathSuffix).Return("2001:db8::/32", nil)
	engine := &engine{metadata: mockMetadata}

	netmask, err := engine.GetIPV6PrefixLength(firstMACAddressSanitized)
	assert.NoError(t, err)
	assert.Equal(t, "32", netmask)
}

func TestGetIPV6GatewayIPFromRoutesOnceRouteListReturnsError(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockLink := mock_netlink.NewMockLink(ctrl)
	mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_V6).Return(nil, errors.New(""))
	engine := &engine{netLink: mockNetLink}

	_, _, err := engine.getIPV6GatewayIPFromRoutesOnce(mockLink, deviceName)
	assert.Error(t, err)
}

func TestGetIPV6GatewayIPFromRoutesOnceRouteListReturnsFalseWhenNotFound(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockLink := mock_netlink.NewMockLink(ctrl)
	ipv6Addr := net.ParseIP(eniIPV6Address)
	ipNet := &net.IPNet{
		IP: ipv6Addr,
	}
	ipv6Gw := net.ParseIP(eniIPV6Gateway)
	routes := []netlink.Route{
		// Dst is set, nothing else is
		netlink.Route{
			Dst: ipNet,
		},
		// Dst is not set, but other fields are
		netlink.Route{
			Dst: &net.IPNet{},
			Src: ipv6Addr,
			Gw:  ipv6Gw,
		},
		// Dst, Src and Gw are all set
		netlink.Route{
			Dst: ipNet,
			Src: ipv6Addr,
			Gw:  ipv6Gw,
		},
	}
	mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_V6).Return(routes, nil)
	engine := &engine{netLink: mockNetLink}

	_, ok, err := engine.getIPV6GatewayIPFromRoutesOnce(mockLink, deviceName)
	assert.NoError(t, err)
	assert.False(t, ok)
}

func TestGetIPV6GatewayIPFromRoutesOnceRouteListReturnsTrueWhenFound(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockLink := mock_netlink.NewMockLink(ctrl)
	ipv6Addr := net.ParseIP(eniIPV6Address)
	ipv6Gw := net.ParseIP(eniIPV6Gateway)
	ipNet := &net.IPNet{
		IP: ipv6Addr,
	}
	routes := []netlink.Route{
		// Dst is set, nothing else is
		netlink.Route{
			Dst: ipNet,
		},
		// Dst is not set, but other fields are
		netlink.Route{
			Dst: &net.IPNet{},
			Src: ipv6Addr,
			Gw:  ipv6Gw,
		},
		// Dst, Src and Gw are all set
		netlink.Route{
			Dst: ipNet,
			Src: ipv6Addr,
			Gw:  ipv6Gw,
		},
		// Only Gw is set, this is what we're looking for
		netlink.Route{
			Gw: ipv6Gw,
		},
	}
	mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_V6).Return(routes, nil)
	engine := &engine{netLink: mockNetLink}

	gateway, ok, err := engine.getIPV6GatewayIPFromRoutesOnce(mockLink, deviceName)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, gateway, eniIPV6Gateway)
}

func TestGetIPV6GatewayIPFromRoutesDoesNotRetryOnError(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockLink := mock_netlink.NewMockLink(ctrl)
	// Expect only one invocation of route list
	mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_V6).Return(nil, errors.New("error"))
	engine := &engine{netLink: mockNetLink}

	_, err := engine.getIPV6GatewayIPFromRoutes(mockLink, deviceName,
		maxTicksForRetrievingIPV6Gateway, ipv6GatewayTickDuration)
	assert.Error(t, err)
}

func TestGetIPV6GatewayIPFromRoutesRetriesWhenNotFound(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockLink := mock_netlink.NewMockLink(ctrl)
	// Expect only 2 invocation of route list
	mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_V6).Return(nil, nil).Times(2)
	engine := &engine{netLink: mockNetLink}

	_, err := engine.getIPV6GatewayIPFromRoutes(mockLink, deviceName, 2, time.Microsecond)
	assert.Error(t, err)
}

func TestGetIPV6GatewayIPFromRoutes(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockLink := mock_netlink.NewMockLink(ctrl)
	ipv6Gw := net.ParseIP(eniIPV6Gateway)
	routes := []netlink.Route{
		netlink.Route{
			Gw: ipv6Gw,
		},
	}

	gomock.InOrder(
		mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_V6).Return(nil, nil),
		mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_V6).Return(routes, nil),
	)
	engine := &engine{netLink: mockNetLink}

	gateway, err := engine.getIPV6GatewayIPFromRoutes(mockLink, deviceName, 2, time.Microsecond)
	assert.NoError(t, err)
	assert.Equal(t, gateway, eniIPV6Gateway)
}

func TestGetIPV6GatewayOnLinkByNameError(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkByName(deviceName).Return(nil, errors.New("error"))
	engine := &engine{
		netLink:                          mockNetLink,
		ipv6GatewayTickDuration:          time.Microsecond,
		maxTicksForRetrievingIPV6Gateway: 2,
	}

	_, err := engine.GetIPV6Gateway(deviceName)
	assert.Error(t, err)
}

func TestGetIPV6GatewayOnGetIPV6GatewayIPFromRoutesError(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockLink := mock_netlink.NewMockLink(ctrl)
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockLink, nil),
		mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_V6).Return(nil, errors.New("error")),
	)
	engine := &engine{
		netLink:                          mockNetLink,
		ipv6GatewayTickDuration:          time.Microsecond,
		maxTicksForRetrievingIPV6Gateway: 2,
	}

	_, err := engine.GetIPV6Gateway(deviceName)
	assert.Error(t, err)
}

func TestGetIPV6GatewayOnGetIPV6GatewayIPFromRoutesNotFound(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockLink := mock_netlink.NewMockLink(ctrl)
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockLink, nil),
		mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_V6).Return(nil, nil).Times(2),
	)
	engine := &engine{
		netLink:                          mockNetLink,
		ipv6GatewayTickDuration:          time.Microsecond,
		maxTicksForRetrievingIPV6Gateway: 2,
	}

	_, err := engine.GetIPV6Gateway(deviceName)
	assert.Error(t, err)
}

func TestGetIPV6GatewayOnGetIPV6GatewayIPFromRoutesFound(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockLink := mock_netlink.NewMockLink(ctrl)
	ipv6Gw := net.ParseIP(eniIPV6Gateway)
	routes := []netlink.Route{
		netlink.Route{
			Gw: ipv6Gw,
		},
	}
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockLink, nil),
		mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_V6).Return(routes, nil),
	)
	engine := &engine{
		netLink:                          mockNetLink,
		ipv6GatewayTickDuration:          time.Microsecond,
		maxTicksForRetrievingIPV6Gateway: 2,
	}

	gateway, err := engine.GetIPV6Gateway(deviceName)
	assert.NoError(t, err)
	assert.Equal(t, gateway, eniIPV6Gateway)
}

func TestIsValidGetIPAddressReturnsErrorOnGetMetadataError(t *testing.T) {
	ctrl, mockMetadata, _, _ := setup(t)
	defer ctrl.Finish()

	suffix := "/suffix"
	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+suffix).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata, metadataMaxRetryCount: 1}

	_, err := engine.doesMACAddressMapToIPAddress(firstMACAddressSanitized, eniIPV4Address, "/suffix")
	assert.Error(t, err)
}

func TestDoesMACAddressMapToIPAddressReturnsFalseWhenNotFound(t *testing.T) {
	ctrl, mockMetadata, _, _ := setup(t)
	defer ctrl.Finish()

	suffix := "/suffix"
	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+suffix).Return("172.31.32.3", nil)
	engine := &engine{metadata: mockMetadata, metadataMaxRetryCount: 1}

	ok, err := engine.doesMACAddressMapToIPAddress(firstMACAddressSanitized, eniIPV4Address, "/suffix")
	assert.NoError(t, err)
	assert.False(t, ok)

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+suffix).Return("2001::68", nil)
	ok, err = engine.doesMACAddressMapToIPAddress(firstMACAddressSanitized, eniIPV6Address, "/suffix")
	assert.NoError(t, err)
	assert.False(t, ok)
}

func TestDoesMACAddressMapToIPAddressReturnsTrueWhenFound(t *testing.T) {
	ctrl, mockMetadata, _, _ := setup(t)
	defer ctrl.Finish()

	suffix := "/suffix"
	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+suffix).Return(eniIPV4Address, nil)
	engine := &engine{metadata: mockMetadata, metadataMaxRetryCount: 1}

	ok, err := engine.doesMACAddressMapToIPAddress(firstMACAddressSanitized, eniIPV4Address, suffix)
	assert.NoError(t, err)
	assert.True(t, ok)

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+suffix).Return(eniIPV6Address, nil)
	ok, err = engine.doesMACAddressMapToIPAddress(firstMACAddressSanitized, eniIPV6Address, suffix)
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestIsValidGetIPAddressRetriesOnGetMetadataError(t *testing.T) {
	ctrl, mockMetadata, _, _ := setup(t)
	defer ctrl.Finish()

	suffix := "/suffix"
	gomock.InOrder(
		// First attempt fails
		mockMetadata.EXPECT().GetMetadata(
			metadataNetworkInterfacesPath+firstMACAddressSanitized+suffix).Return(
			"", errors.New("error")),
		// Second attempt succeeds
		mockMetadata.EXPECT().GetMetadata(
			metadataNetworkInterfacesPath+firstMACAddressSanitized+suffix).Return(
			eniIPV4Address, nil),
	)
	engine := &engine{metadata: mockMetadata,
		metadataMaxRetryCount:          2,
		metadataDurationBetweenRetries: time.Microsecond}

	ok, err := engine.doesMACAddressMapToIPAddress(firstMACAddressSanitized, eniIPV4Address, "/suffix")
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestIsValidGetIPV4AddressReturnsError(t *testing.T) {
	ctrl, mockMetadata, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV4AddressesSuffix).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata, metadataMaxRetryCount: 1}

	_, err := engine.DoesMACAddressMapToIPV4Address(firstMACAddressSanitized, eniIPV4Address)
	assert.Error(t, err)
}

func TestIsValidGetIPV4Address(t *testing.T) {
	ctrl, mockMetadata, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV4AddressesSuffix).Return(eniIPV4Address, nil)
	engine := &engine{metadata: mockMetadata, metadataMaxRetryCount: 1}

	ok, err := engine.DoesMACAddressMapToIPV4Address(firstMACAddressSanitized, eniIPV4Address)
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestIsValidGetIPV6AddressReturnsError(t *testing.T) {
	ctrl, mockMetadata, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV6AddressesSuffix).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata, metadataMaxRetryCount: 1}

	_, err := engine.DoesMACAddressMapToIPV6Address(firstMACAddressSanitized, eniIPV6Address)
	assert.Error(t, err)
}

func TestIsValidGetIPV6Address(t *testing.T) {
	ctrl, mockMetadata, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV6AddressesSuffix).Return(eniIPV6Address, nil)
	engine := &engine{metadata: mockMetadata, metadataMaxRetryCount: 1}

	ok, err := engine.DoesMACAddressMapToIPV6Address(firstMACAddressSanitized, eniIPV6Address)
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestSetupContainerNamespaceFailsOnLinkByNameError(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkByName(deviceName).Return(nil, errors.New("error"))
	engine := &engine{netLink: mockNetLink}
	err := engine.SetupContainerNamespace(&skel.CmdArgs{
		Netns:  "ns1",
		IfName: "eth0",
	}, deviceName, eniMACAddress, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway, false, false)
	assert.Error(t, err)
}

func TestSetupContainerNamespaceFailsOnGetNSError(t *testing.T) {
	ctrl, _, mockNS, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockLink := mock_netlink.NewMockLink(ctrl)
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockLink, nil),
		mockNS.EXPECT().GetNS("ns1").Return(nil, errors.New("error")),
	)
	engine := &engine{ns: mockNS, netLink: mockNetLink}
	err := engine.SetupContainerNamespace(&skel.CmdArgs{
		Netns:  "ns1",
		IfName: "eth0",
	}, deviceName, eniMACAddress, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway, false, false)
	assert.Error(t, err)
}

func TestSetupContainerNamespaceFailsOnLinksetNsFdError(t *testing.T) {
	ctrl, _, mockNS, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockENILink := mock_netlink.NewMockLink(ctrl)
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	var fd uintptr
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNS.EXPECT().GetNS("ns1").Return(mockNetNS, nil),
		mockNetNS.EXPECT().Fd().Return(fd),
		mockNetLink.EXPECT().LinkSetNsFd(mockENILink, int(fd)).Return(errors.New("error")),
	)
	engine := &engine{ns: mockNS, netLink: mockNetLink}
	err := engine.SetupContainerNamespace(&skel.CmdArgs{
		Netns:  "ns1",
		IfName: "eth0",
	}, deviceName, eniMACAddress, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway, false, false)
	assert.Error(t, err)
}

func TestSetupContainerNamespaceFailsOnParseAddrError(t *testing.T) {
	ctrl, _, mockNS, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockENILink := mock_netlink.NewMockLink(ctrl)
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	var fd uintptr
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNS.EXPECT().GetNS("ns1").Return(mockNetNS, nil),
		mockNetNS.EXPECT().Fd().Return(fd),
		mockNetLink.EXPECT().LinkSetNsFd(mockENILink, int(fd)).Return(nil),
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(nil, errors.New("error")),
	)
	engine := &engine{ns: mockNS, netLink: mockNetLink}
	err := engine.SetupContainerNamespace(&skel.CmdArgs{
		Netns:  "ns1",
		IfName: "eth0",
	}, deviceName, eniMACAddress, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway, false, false)
	assert.Error(t, err)
}

func TestSetupContainerNamespaceFailsOnWithNetNSPathError(t *testing.T) {
	ctrl, _, mockNS, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockENILink := mock_netlink.NewMockLink(ctrl)
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	var fd uintptr
	ipv4Addr := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNS.EXPECT().GetNS("ns1").Return(mockNetNS, nil),
		mockNetNS.EXPECT().Fd().Return(fd),
		mockNetLink.EXPECT().LinkSetNsFd(mockENILink, int(fd)).Return(nil),
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Addr, nil),
		mockNS.EXPECT().WithNetNSPath("ns1", gomock.Any()).Return(errors.New("error")),
	)
	engine := &engine{ns: mockNS, netLink: mockNetLink}
	err := engine.SetupContainerNamespace(&skel.CmdArgs{
		Netns:  "ns1",
		IfName: "eth0",
	}, deviceName, eniMACAddress, eniIPV4CIDRBlock, "", eniIPV4Gateway, "", false, false)
	assert.Error(t, err)
}

func TestSetupContainerNamespaceNoIPV6(t *testing.T) {
	ctrl, _, mockNS, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockENILink := mock_netlink.NewMockLink(ctrl)
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	var fd uintptr
	ipv4Addr := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNS.EXPECT().GetNS("ns1").Return(mockNetNS, nil),
		mockNetNS.EXPECT().Fd().Return(fd),
		mockNetLink.EXPECT().LinkSetNsFd(mockENILink, int(fd)).Return(nil),
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Addr, nil),
		mockNS.EXPECT().WithNetNSPath("ns1", gomock.Any()).Return(nil),
	)
	engine := &engine{ns: mockNS, netLink: mockNetLink}
	err := engine.SetupContainerNamespace(&skel.CmdArgs{
		Netns:  "ns1",
		IfName: "eth0",
	}, deviceName, eniMACAddress, eniIPV4CIDRBlock, "", eniIPV4Gateway, "", false, false)
	assert.NoError(t, err)
}

func TestSetupContainerNamespace(t *testing.T) {
	ctrl, _, mockNS, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockENILink := mock_netlink.NewMockLink(ctrl)
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	var fd uintptr
	ipv4Addr := &netlink.Addr{}
	ipv6Addr := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNS.EXPECT().GetNS("ns1").Return(mockNetNS, nil),
		mockNetNS.EXPECT().Fd().Return(fd),
		mockNetLink.EXPECT().LinkSetNsFd(mockENILink, int(fd)).Return(nil),
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Addr, nil),
		mockNetLink.EXPECT().ParseAddr(eniIPV6CIDRBlock).Return(ipv6Addr, nil),
		mockNS.EXPECT().WithNetNSPath("ns1", gomock.Any()).Return(nil),
	)
	engine := &engine{ns: mockNS, netLink: mockNetLink}
	err := engine.SetupContainerNamespace(&skel.CmdArgs{
		Netns:  "ns1",
		IfName: "eth0",
	}, deviceName, eniMACAddress, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway, false, false)
	assert.NoError(t, err)
}

func TestSetupContainerNamespaceStayDown(t *testing.T) {
	ctrl, _, mockNS, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockENILink := mock_netlink.NewMockLink(ctrl)
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	var fd uintptr
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNS.EXPECT().GetNS("ns1").Return(mockNetNS, nil),
		mockNetNS.EXPECT().Fd().Return(fd),
		mockNetLink.EXPECT().LinkSetNsFd(mockENILink, int(fd)).Return(nil),
	)
	engine := &engine{ns: mockNS, netLink: mockNetLink}
	err := engine.SetupContainerNamespace(&skel.CmdArgs{
		Netns:  "ns1",
		IfName: "eth0",
	}, deviceName, eniMACAddress, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway, false, true)
	assert.NoError(t, err)
}

func TestSetupNamespaceClosureCreationFailsOnIPV4ParseAddrError(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(nil, errors.New("error"))
	_, err := newSetupNamespaceClosureContext(mockNetLink, "eth0", deviceName, eniMACAddress, eniIPV4CIDRBlock, "", eniIPV4Gateway, "", false)
	assert.Error(t, err)
}

func TestSetupNamespaceClosureCreationFailsOnIPV4ParseGatewayError(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	ipv4Addr := &netlink.Addr{}
	mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Addr, nil)
	// Gateway is an empty string, so we expect this method to fail
	_, err := newSetupNamespaceClosureContext(mockNetLink, "eth0", deviceName, eniMACAddress, eniIPV4CIDRBlock, "", "", "", false)
	assert.Error(t, err)
}

func TestSetupNamespaceClosureCreationFailsOnIPV6ParseAddrError(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	ipv4Addr := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Addr, nil),
		mockNetLink.EXPECT().ParseAddr(eniIPV6CIDRBlock).Return(nil, errors.New("error")),
	)
	_, err := newSetupNamespaceClosureContext(mockNetLink, "eth0", deviceName, eniMACAddress, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway, false)
	assert.Error(t, err)
}

func TestSetupNamespaceClosureCreationFailsOnIPV6ParseGatewayError(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	ipv4Addr := &netlink.Addr{}
	ipv6Addr := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Addr, nil),
		mockNetLink.EXPECT().ParseAddr(eniIPV6CIDRBlock).Return(ipv6Addr, nil),
	)
	// Gateway is an empty string, so we expect this method to fail
	_, err := newSetupNamespaceClosureContext(mockNetLink, "eth0", deviceName, eniMACAddress, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, "", false)
	assert.Error(t, err)
}

func TestSetupNamespaceClosureRunFailsOnLinkByNameError(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	ipv4Addr := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Addr, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(nil, errors.New("error")),
	)
	closure, err := newSetupNamespaceClosureContext(mockNetLink, "eth0", deviceName, eniMACAddress, eniIPV4CIDRBlock, "", eniIPV4Gateway, "", false)
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestSetupNamespaceClosureRunFailsOnIPV4AddrAddError(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().LinkSetName(mockENILink, "eth0").Return(nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(errors.New("error")),
	)
	closure, err := newSetupNamespaceClosureContext(mockNetLink, "eth0", deviceName, eniMACAddress, eniIPV4CIDRBlock, "", eniIPV4Gateway, "", false)
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestSetupNamespaceClosureRunFailsOnIPV6AddrAddError(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	ipv6Address := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().ParseAddr(eniIPV6CIDRBlock).Return(ipv6Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().LinkSetName(mockENILink, "eth0").Return(nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv6Address).Return(errors.New("error")),
	)
	closure, err := newSetupNamespaceClosureContext(mockNetLink, "eth0", deviceName, eniMACAddress, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway, false)
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestSetupNamespaceClosureRunFailsOnLinkSetupError(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().LinkSetName(mockENILink, "eth0").Return(nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(mockENILink).Return(errors.New("error")),
	)
	closure, err := newSetupNamespaceClosureContext(mockNetLink, "eth0", deviceName, eniMACAddress, eniIPV4CIDRBlock, "", eniIPV4Gateway, "", false)
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestSetupNamespaceClosureRunFailsOnBlackholeRouteAddError(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	_, imdsNetwork, err := net.ParseCIDR(instanceMetadataEndpoint)
	assert.NoError(t, err)
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().LinkSetName(mockENILink, "eth0").Return(nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(mockENILink).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Nil(t, route.Gw)
			assert.Equal(t, imdsNetwork.String(), route.Dst.String())
			assert.Equal(t, syscall.RTN_BLACKHOLE, route.Type)
		}).Return(errors.New("error")),
	)
	closure, err := newSetupNamespaceClosureContext(mockNetLink, "eth0", deviceName, eniMACAddress, eniIPV4CIDRBlock, "", eniIPV4Gateway, "", true)
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestSetupNamespaceClosureRunFailsOnIPV4RouteAddError(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().LinkSetName(mockENILink, "eth0").Return(nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(mockENILink).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, route.Gw.String(), eniIPV4Gateway)
		}).Return(errors.New("error")),
	)
	closure, err := newSetupNamespaceClosureContext(mockNetLink, "eth0", deviceName, eniMACAddress, eniIPV4CIDRBlock, "", eniIPV4Gateway, "", false)
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestSetupNamespaceClosureRunFailsOnIPV6RouteAddError(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	ipv6Address := &netlink.Addr{}
	eniLinkIndex := 1
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().ParseAddr(eniIPV6CIDRBlock).Return(ipv6Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().LinkSetName(mockENILink, "eth0").Return(nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv6Address).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(mockENILink).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, route.Gw.String(), eniIPV4Gateway)
		}).Return(nil),
		mockENILink.EXPECT().Attrs().Return(&netlink.LinkAttrs{Index: eniLinkIndex}),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, route.Gw.String(), eniIPV6Gateway)
			assert.Equal(t, route.LinkIndex, eniLinkIndex)
		}).Return(errors.New("error")),
	)
	closure, err := newSetupNamespaceClosureContext(mockNetLink, "eth0", deviceName, eniMACAddress, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway, false)
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestIsRouteExistsError(t *testing.T) {
	for _, tc := range []struct {
		err      error
		expected bool
	}{
		{errors.New("error"), false},
		{syscall.Errno(syscall.EEXIST), true},
	} {
		t.Run(fmt.Sprintf("Error %v returns %t for isRouteExistsError", tc.err, tc.expected), func(t *testing.T) {
			assert.Equal(t, tc.expected, isRouteExistsError(tc.err))
		})
	}
}

func TestSetupNamespaceClosureRunNoIPV6(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().LinkSetName(mockENILink, "eth0").Return(nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(mockENILink).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, route.Gw.String(), eniIPV4Gateway)
		}).Return(nil),
	)
	closure, err := newSetupNamespaceClosureContext(mockNetLink, "eth0", deviceName, eniMACAddress, eniIPV4CIDRBlock, "", eniIPV4Gateway, "", false)
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.NoError(t, err)
}

func TestSetupNamespaceClosureRunBlockIMDS(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	ipv6Address := &netlink.Addr{}
	eniLinkIndex := 1
	_, imdsNetwork, err := net.ParseCIDR(instanceMetadataEndpoint)
	assert.NoError(t, err)
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().ParseAddr(eniIPV6CIDRBlock).Return(ipv6Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().LinkSetName(mockENILink, "eth0").Return(nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv6Address).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(mockENILink).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Nil(t, route.Gw)
			assert.Equal(t, imdsNetwork.String(), route.Dst.String())
			assert.Equal(t, syscall.RTN_BLACKHOLE, route.Type)
		}).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, route.Gw.String(), eniIPV4Gateway)
		}).Return(nil),
		mockENILink.EXPECT().Attrs().Return(&netlink.LinkAttrs{Index: eniLinkIndex}),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, route.Gw.String(), eniIPV6Gateway)
			assert.Equal(t, route.LinkIndex, eniLinkIndex)
		}).Return(nil),
	)
	closure, err := newSetupNamespaceClosureContext(mockNetLink, "eth0", deviceName, eniMACAddress, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway, true)
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.NoError(t, err)
}

func TestSetupNamespaceClosureRun(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	ipv6Address := &netlink.Addr{}
	eniLinkIndex := 1
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().ParseAddr(eniIPV6CIDRBlock).Return(ipv6Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().LinkSetName(mockENILink, "eth0").Return(nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv6Address).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(mockENILink).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, route.Gw.String(), eniIPV4Gateway)
		}).Return(nil),
		mockENILink.EXPECT().Attrs().Return(&netlink.LinkAttrs{Index: eniLinkIndex}),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, route.Gw.String(), eniIPV6Gateway)
			assert.Equal(t, route.LinkIndex, eniLinkIndex)
		}).Return(nil),
	)
	closure, err := newSetupNamespaceClosureContext(mockNetLink, "eth0", deviceName, eniMACAddress, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway, false)
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.NoError(t, err)
}

func TestGetLinkByHardwareAddressFailsOnListLinkError(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	hwAddress := net.HardwareAddr{}

	mockNetLink.EXPECT().LinkList().Return(nil, errors.New("error"))
	_, err := getLinkByHardwareAddress(mockNetLink, hwAddress)
	assert.Error(t, err)
}

func TestGetLinkByHardwareAddressFailsWhenLinkNotFound(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	lo := mock_netlink.NewMockLink(ctrl)
	eth1 := mock_netlink.NewMockLink(ctrl)

	loAddress, err := net.ParseMAC(loMACAddress)
	assert.NoError(t, err)
	eth1Address, err := net.ParseMAC(eniMACAddress)
	assert.NoError(t, err)
	hwAddress, err := net.ParseMAC(unknownMACAddress)
	assert.NoError(t, err)
	gomock.InOrder(
		mockNetLink.EXPECT().LinkList().Return([]netlink.Link{lo, eth1}, nil),
		lo.EXPECT().Attrs().Return(&netlink.LinkAttrs{HardwareAddr: loAddress}),
		eth1.EXPECT().Attrs().Return(&netlink.LinkAttrs{HardwareAddr: eth1Address}),
	)

	_, err = getLinkByHardwareAddress(mockNetLink, hwAddress)
	assert.Error(t, err)
}

func TestGetLinkByHardwareAddress(t *testing.T) {
	ctrl, _, _, mockNetLink := setup(t)
	defer ctrl.Finish()

	lo := mock_netlink.NewMockLink(ctrl)
	eth1 := mock_netlink.NewMockLink(ctrl)

	loAddress, err := net.ParseMAC(loMACAddress)
	assert.NoError(t, err)
	eth1Address, err := net.ParseMAC(eniMACAddress)
	assert.NoError(t, err)
	gomock.InOrder(
		mockNetLink.EXPECT().LinkList().Return([]netlink.Link{lo, eth1}, nil),
		lo.EXPECT().Attrs().Return(&netlink.LinkAttrs{HardwareAddr: loAddress}),
		eth1.EXPECT().Attrs().Return(&netlink.LinkAttrs{HardwareAddr: eth1Address}),
	)

	_, err = getLinkByHardwareAddress(mockNetLink, eth1Address)
	assert.NoError(t, err)
}
