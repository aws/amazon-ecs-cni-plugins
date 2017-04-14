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
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/aws/amazon-ecs-cni-plugins/pkg/cninswrapper/mocks"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/cninswrapper/mocks_netns"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/ec2metadata/mocks"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/execwrapper/mocks"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/ioutilwrapper/mocks_ioutilwrapper"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/netlinkwrapper/mocks"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/netlinkwrapper/mocks_link"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/oswrapper/mocks"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

const (
	deviceName                    = "eth1"
	firstENIID                    = "eni1"
	secondENIID                   = "eni2"
	firstMACAddress               = "mac1/"
	firstMACAddressSanitized      = "mac1"
	secondMACAddress              = "mac2/"
	secondMACAddressSanitized     = "mac2"
	eniIPV4Address                = "10.11.12.13"
	eniIPV6Address                = "2001:db8::68"
	eniIPV4Gateway                = "10.10.10.10"
	eniIPV6Gateway                = "2001:db9::68"
	eniSubnetMask                 = "20"
	eniIPV4CIDRBlock              = "10.10.10.10/20"
	eniIPV6CIDRBlock              = "2001:db8::68/32"
	eniMACAddress                 = "01:23:45:67:89:ab"
	unknownMACAddress             = "01:23:45:67:89:cd"
	loMACAddress                  = "00:00:00:00:00:00"
	invalidMACAddress             = "01:23:45:67:89"
	dhclientV4PIDFileContents     = "1123\n"
	dhclientV4PID                 = 1123
	dhclientV6PIDFileContents     = "2358\n"
	dhclientV6PID                 = 2358
	invalidDHClientPIDFieContents = "abcd"
)

func setup(t *testing.T) (*gomock.Controller,
	*mock_ec2metadata.MockEC2Metadata,
	*mock_ioutilwrapper.MockIOUtil,
	*mock_cninswrapper.MockNS,
	*mock_netlinkwrapper.MockNetLink,
	*mock_execwrapper.MockExec,
	*mock_oswrapper.MockOS) {
	ctrl := gomock.NewController(t)
	return ctrl,
		mock_ec2metadata.NewMockEC2Metadata(ctrl),
		mock_ioutilwrapper.NewMockIOUtil(ctrl),
		mock_cninswrapper.NewMockNS(ctrl),
		mock_netlinkwrapper.NewMockNetLink(ctrl),
		mock_execwrapper.NewMockExec(ctrl),
		mock_oswrapper.NewMockOS(ctrl)
}

func TestCreate(t *testing.T) {
	ctrl, mockMetadata, mockIOUtil, mockNS, mockNetLink, mockExec, mockOS := setup(t)
	defer ctrl.Finish()

	engine := create(mockMetadata, mockIOUtil, mockNetLink, mockNS, mockExec, mockOS)
	assert.NotNil(t, engine)
}

func TestIsDHClientInPathReturnsFalseOnLookPathError(t *testing.T) {
	ctrl, _, _, _, _, mockExec, _ := setup(t)
	defer ctrl.Finish()

	mockExec.EXPECT().LookPath(dhclientExecutableName).Return("", errors.New("error"))
	engine := &engine{exec: mockExec}

	ok := engine.IsDHClientInPath()
	assert.False(t, ok)
}

func TestIsDHClientInPath(t *testing.T) {
	ctrl, _, _, _, _, mockExec, _ := setup(t)
	defer ctrl.Finish()

	mockExec.EXPECT().LookPath(dhclientExecutableName).Return("dhclient", nil)
	engine := &engine{exec: mockExec}

	ok := engine.IsDHClientInPath()
	assert.True(t, ok)
}

func TestGetAllMACAddressesReturnsErrorOnGetMetadataError(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata}

	_, err := engine.GetAllMACAddresses()
	assert.Error(t, err)
}

func TestGetAllMACAddresses(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath).Return("a\nb", nil)
	engine := &engine{metadata: mockMetadata}

	macs, err := engine.GetAllMACAddresses()
	assert.NoError(t, err)
	assert.NotEmpty(t, macs)
	assert.Len(t, macs, 2)
}

func TestGetMACAddressOfENIReturnsErrorOnGetMetadataError(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddress+metadataNetworkInterfaceIDPathSuffix).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata}

	_, err := engine.GetMACAddressOfENI([]string{firstMACAddress}, firstENIID)
	assert.Error(t, err)
	_, ok := err.(*unmappedMACAddressError)
	assert.True(t, ok)
}

func TestGetMACAddressOfENIReturnsErrorWhenNotFound(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddress+metadataNetworkInterfaceIDPathSuffix).Return(firstENIID, nil)
	engine := &engine{metadata: mockMetadata}

	_, err := engine.GetMACAddressOfENI([]string{firstMACAddress}, secondENIID)
	assert.Error(t, err)
	_, ok := err.(*unmappedMACAddressError)
	assert.True(t, ok)
}

func TestGetMACAddressOfENI(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _, _ := setup(t)
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
	ctrl, _, _, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	engine := &engine{}

	_, err := engine.GetInterfaceDeviceName("")
	assert.Error(t, err)
}

func TestGetInterfaceDeviceNameReturnsErrorOnLinkListErrort(t *testing.T) {
	ctrl, _, _, _, mockNetLink, _, _ := setup(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkList().Return(nil, errors.New("error"))
	engine := &engine{netLink: mockNetLink}

	_, err := engine.GetInterfaceDeviceName(eniMACAddress)
	assert.Error(t, err)
}

func TestGetInterfaceDeviceNameReturnsErrorWhenDeviceNotFound(t *testing.T) {
	ctrl, _, _, _, mockNetLink, _, _ := setup(t)
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
	ctrl, _, _, _, mockNetLink, _, _ := setup(t)
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

func TestGetIPV4GatewayNetMaskInternalReturnsErrorOnMalformedCIDR(t *testing.T) {
	_, _, err := getIPV4GatewayNetmask("1.1.1.1")
	assert.Error(t, err)
}

func TestGetIPV4GatewayNetMaskInternalReturnsErrorOnMalformedNetmaskInCIDR(t *testing.T) {
	_, _, err := getIPV4GatewayNetmask("1.1.1.1/")
	assert.Error(t, err)
}

func TestGetIPV4GatewayNetMaskInternalReturnsErrorOnMalformedCIDRBlockInCIDR(t *testing.T) {
	_, _, err := getIPV4GatewayNetmask("1.1.1/1")
	assert.Error(t, err)
}

func TestGetIPV4GatewayNetMaskInternalReturnsErrorOnEmptyRouterInCIDR(t *testing.T) {
	_, _, err := getIPV4GatewayNetmask("1.1.1./1")
	assert.Error(t, err)
}

func TestGetIPV4GatewayNetMaskInternalReturnsErrorOnInvalidRouterInCIDR(t *testing.T) {
	_, _, err := getIPV4GatewayNetmask("1.1.1.foo/1")
	assert.Error(t, err)
}

func TestGetIPV4GatewayNetMaskInternalReturnsErrorOnInvalidCIDRBlock(t *testing.T) {
	_, _, err := getIPV4GatewayNetmask("10.0.64.0/29")
	assert.Error(t, err)
	_, _, err = getIPV4GatewayNetmask("10.0.64.0/15")
	assert.Error(t, err)
}

func TestGetIPV4GatewayNetMaskInternal(t *testing.T) {
	gateway, netmask, err := getIPV4GatewayNetmask("10.0.1.64/26")
	assert.NoError(t, err)
	assert.Equal(t, gateway, "10.0.1.65")
	assert.Equal(t, netmask, "26")
}

func TestGetIPV4GatewayNetMaskReturnsErrorOnGetMetadataError(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV4CIDRPathSuffix).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata}

	_, _, err := engine.GetIPV4GatewayNetmask(firstMACAddressSanitized)
	assert.Error(t, err)
	_, ok := err.(*parseIPV4GatewayNetmaskError)
	assert.False(t, ok)
}

func TestGetIPV4GatewayNetMaskReturnsErrorWhenUnableToParseCIDRNetmaskResponse(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	engine := &engine{metadata: mockMetadata}
	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV4CIDRPathSuffix).Return("1.1.1.1", nil)
	_, _, err := engine.GetIPV4GatewayNetmask(firstMACAddressSanitized)
	assert.Error(t, err)
	_, ok := err.(*parseIPV4GatewayNetmaskError)
	assert.False(t, ok)
}

func TestGetIPV4GatewayNetMaskWhenUnableToParseIPV6CIDRNetmaskResponse(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV4CIDRPathSuffix).Return("2001:db8::/32", nil)
	engine := &engine{metadata: mockMetadata}

	_, _, err := engine.GetIPV4GatewayNetmask(firstMACAddressSanitized)
	assert.Error(t, err)
	_, ok := err.(*parseIPV4GatewayNetmaskError)
	assert.True(t, ok)
}

func TestGetIPV4GatewayNetMask(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _, _ := setup(t)
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
	ctrl, mockMetadata, _, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV6CIDRPathSuffix).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata}

	_, err := engine.GetIPV6PrefixLength(firstMACAddressSanitized)
	assert.Error(t, err)
}

func TestGetIPV6NetMaskReturnsErrorWhenUnableToParseCIDRNetmaskResponse(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	engine := &engine{metadata: mockMetadata}
	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV6CIDRPathSuffix).Return("2001:db8::", nil)
	_, err := engine.GetIPV6PrefixLength(firstMACAddressSanitized)
	assert.Error(t, err)
}

func TestGetIPV6NetMask(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(
		metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV6CIDRPathSuffix).Return("2001:db8::/32", nil)
	engine := &engine{metadata: mockMetadata}

	netmask, err := engine.GetIPV6PrefixLength(firstMACAddressSanitized)
	assert.NoError(t, err)
	assert.Equal(t, "32", netmask)
}

func TestGetIPV6GatewayIPFromRoutesOnceRouteListReturnsError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, _, _ := setup(t)
	defer ctrl.Finish()

	mockLink := mock_netlink.NewMockLink(ctrl)
	mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_V6).Return(nil, errors.New(""))
	engine := &engine{netLink: mockNetLink}

	_, _, err := engine.getIPV6GatewayIPFromRoutesOnce(mockLink, deviceName)
	assert.Error(t, err)
}

func TestGetIPV6GatewayIPFromRoutesOnceRouteListReturnsFalseWhenNotFound(t *testing.T) {
	ctrl, _, _, _, mockNetLink, _, _ := setup(t)
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
	ctrl, _, _, _, mockNetLink, _, _ := setup(t)
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
	ctrl, _, _, _, mockNetLink, _, _ := setup(t)
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
	ctrl, _, _, _, mockNetLink, _, _ := setup(t)
	defer ctrl.Finish()

	mockLink := mock_netlink.NewMockLink(ctrl)
	// Expect only 2 invocation of route list
	mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_V6).Return(nil, nil).Times(2)
	engine := &engine{netLink: mockNetLink}

	_, err := engine.getIPV6GatewayIPFromRoutes(mockLink, deviceName, 2, time.Microsecond)
	assert.Error(t, err)
}

func TestGetIPV6GatewayIPFromRoutes(t *testing.T) {
	ctrl, _, _, _, mockNetLink, _, _ := setup(t)
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
	ctrl, _, _, _, mockNetLink, _, _ := setup(t)
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
	ctrl, _, _, _, mockNetLink, _, _ := setup(t)
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
	ctrl, _, _, _, mockNetLink, _, _ := setup(t)
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
	ctrl, _, _, _, mockNetLink, _, _ := setup(t)
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
	ctrl, mockMetadata, _, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	suffix := "/suffix"
	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+suffix).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata}

	_, err := engine.doesMACAddressMapToIPAddress(firstMACAddressSanitized, eniIPV4Address, "/suffix")
	assert.Error(t, err)
}

func TestDoesMACAddressMapToIPAddressReturnsFalseWhenNotFound(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	suffix := "/suffix"
	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+suffix).Return("172.31.32.3", nil)
	engine := &engine{metadata: mockMetadata}

	ok, err := engine.doesMACAddressMapToIPAddress(firstMACAddressSanitized, eniIPV4Address, "/suffix")
	assert.NoError(t, err)
	assert.False(t, ok)

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+suffix).Return("2001::68", nil)
	ok, err = engine.doesMACAddressMapToIPAddress(firstMACAddressSanitized, eniIPV6Address, "/suffix")
	assert.NoError(t, err)
	assert.False(t, ok)
}

func TestDoesMACAddressMapToIPAddressReturnsTrueWhenFound(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	suffix := "/suffix"
	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+suffix).Return(eniIPV4Address, nil)
	engine := &engine{metadata: mockMetadata}

	ok, err := engine.doesMACAddressMapToIPAddress(firstMACAddressSanitized, eniIPV4Address, suffix)
	assert.NoError(t, err)
	assert.True(t, ok)

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+suffix).Return(eniIPV6Address, nil)
	ok, err = engine.doesMACAddressMapToIPAddress(firstMACAddressSanitized, eniIPV6Address, suffix)
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestIsValidGetIPV4AddressReturnsError(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV4AddressesSuffix).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata}

	_, err := engine.DoesMACAddressMapToIPV4Address(firstMACAddressSanitized, eniIPV4Address)
	assert.Error(t, err)
}

func TestIsValidGetIPV4Address(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV4AddressesSuffix).Return(eniIPV4Address, nil)
	engine := &engine{metadata: mockMetadata}

	ok, err := engine.DoesMACAddressMapToIPV4Address(firstMACAddressSanitized, eniIPV4Address)
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestIsValidGetIPV6AddressReturnsError(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV6AddressesSuffix).Return("", errors.New("error"))
	engine := &engine{metadata: mockMetadata}

	_, err := engine.DoesMACAddressMapToIPV6Address(firstMACAddressSanitized, eniIPV6Address)
	assert.Error(t, err)
}

func TestIsValidGetIPV6Address(t *testing.T) {
	ctrl, mockMetadata, _, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockMetadata.EXPECT().GetMetadata(metadataNetworkInterfacesPath+firstMACAddressSanitized+metadataNetworkInterfaceIPV6AddressesSuffix).Return(eniIPV6Address, nil)
	engine := &engine{metadata: mockMetadata}

	ok, err := engine.DoesMACAddressMapToIPV6Address(firstMACAddressSanitized, eniIPV6Address)
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestSetupContainerNamespaceFailsOnLinkByNameError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, _, _ := setup(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkByName(deviceName).Return(nil, errors.New("error"))
	engine := &engine{netLink: mockNetLink}
	err := engine.SetupContainerNamespace("ns1", deviceName, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway)
	assert.Error(t, err)
}

func TestSetupContainerNamespaceFailsOnGetNSError(t *testing.T) {
	ctrl, _, _, mockNS, mockNetLink, _, _ := setup(t)
	defer ctrl.Finish()

	mockLink := mock_netlink.NewMockLink(ctrl)
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockLink, nil),
		mockNS.EXPECT().GetNS("ns1").Return(nil, errors.New("error")),
	)
	engine := &engine{ns: mockNS, netLink: mockNetLink}
	err := engine.SetupContainerNamespace("ns1", deviceName, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway)
	assert.Error(t, err)
}

func TestSetupContainerNamespaceFailsOnLinksetNsFdError(t *testing.T) {
	ctrl, _, _, mockNS, mockNetLink, _, _ := setup(t)
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
	err := engine.SetupContainerNamespace("ns1", deviceName, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway)
	assert.Error(t, err)
}

func TestSetupContainerNamespaceFailsOnParseAddrError(t *testing.T) {
	ctrl, _, _, mockNS, mockNetLink, _, _ := setup(t)
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
	err := engine.SetupContainerNamespace("ns1", deviceName, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway)
	assert.Error(t, err)
}

func TestSetupContainerNamespaceFailsOnWithNetNSPathError(t *testing.T) {
	ctrl, _, _, mockNS, mockNetLink, _, _ := setup(t)
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
	err := engine.SetupContainerNamespace("ns1", deviceName, eniIPV4CIDRBlock, "", eniIPV4Gateway, "")
	assert.Error(t, err)
}

func TestSetupContainerNamespaceNoIPV6(t *testing.T) {
	ctrl, _, _, mockNS, mockNetLink, _, _ := setup(t)
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
	err := engine.SetupContainerNamespace("ns1", deviceName, eniIPV4CIDRBlock, "", eniIPV4Gateway, "")
	assert.NoError(t, err)
}

func TestSetupContainerNamespace(t *testing.T) {
	ctrl, _, _, mockNS, mockNetLink, _, _ := setup(t)
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
	err := engine.SetupContainerNamespace("ns1", deviceName, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway)
	assert.NoError(t, err)
}

func TestSetupNamespaceClosureCreationFailsOnIPV4ParseAddrError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, mockExec, _ := setup(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(nil, errors.New("error"))
	_, err := newSetupNamespaceClosureContext(mockNetLink, mockExec, deviceName, eniIPV4CIDRBlock, "", eniIPV4Gateway, "")
	assert.Error(t, err)
}

func TestSetupNamespaceClosureCreationFailsOnIPV4ParseGatewayError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, mockExec, _ := setup(t)
	defer ctrl.Finish()

	ipv4Addr := &netlink.Addr{}
	mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Addr, nil)
	// Gateway is an empty string, so we expect this method to fail
	_, err := newSetupNamespaceClosureContext(mockNetLink, mockExec, deviceName, eniIPV4CIDRBlock, "", "", "")
	assert.Error(t, err)
}

func TestSetupNamespaceClosureCreationFailsOnIPV6ParseAddrError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, mockExec, _ := setup(t)
	defer ctrl.Finish()

	ipv4Addr := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Addr, nil),
		mockNetLink.EXPECT().ParseAddr(eniIPV6CIDRBlock).Return(nil, errors.New("error")),
	)
	_, err := newSetupNamespaceClosureContext(mockNetLink, mockExec, deviceName, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway)
	assert.Error(t, err)
}

func TestSetupNamespaceClosureCreationFailsOnIPV6ParseGatewayError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, mockExec, _ := setup(t)
	defer ctrl.Finish()

	ipv4Addr := &netlink.Addr{}
	ipv6Addr := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Addr, nil),
		mockNetLink.EXPECT().ParseAddr(eniIPV6CIDRBlock).Return(ipv6Addr, nil),
	)
	// Gateway is an empty string, so we expect this method to fail
	_, err := newSetupNamespaceClosureContext(mockNetLink, mockExec, deviceName, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, "")
	assert.Error(t, err)
}

func TestSetupNamespaceClosureRunFailsOnLinkByNameError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, mockExec, _ := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	ipv4Addr := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Addr, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(nil, errors.New("error")),
	)
	closure, err := newSetupNamespaceClosureContext(mockNetLink, mockExec, deviceName, eniIPV4CIDRBlock, "", eniIPV4Gateway, "")
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestSetupNamespaceClosureRunFailsOnIPV4AddrAddError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, mockExec, _ := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(errors.New("error")),
	)
	closure, err := newSetupNamespaceClosureContext(mockNetLink, mockExec, deviceName, eniIPV4CIDRBlock, "", eniIPV4Gateway, "")
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestSetupNamespaceClosureRunFailsOnIPV6AddrAddError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, mockExec, _ := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	ipv6Address := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().ParseAddr(eniIPV6CIDRBlock).Return(ipv6Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv6Address).Return(errors.New("error")),
	)
	closure, err := newSetupNamespaceClosureContext(mockNetLink, mockExec, deviceName, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway)
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestSetupNamespaceClosureRunFailsOnLinkSetupError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, mockExec, _ := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(mockENILink).Return(errors.New("error")),
	)
	closure, err := newSetupNamespaceClosureContext(mockNetLink, mockExec, deviceName, eniIPV4CIDRBlock, "", eniIPV4Gateway, "")
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestSetupNamespaceClosureRunFailsOnIPV4RouteAddError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, mockExec, _ := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(mockENILink).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, route.Gw.String(), eniIPV4Gateway)
		}).Return(errors.New("error")),
	)
	closure, err := newSetupNamespaceClosureContext(mockNetLink, mockExec, deviceName, eniIPV4CIDRBlock, "", eniIPV4Gateway, "")
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestGetDHClientV4Args(t *testing.T) {
	args := constructDHClientV4Args("eth1")
	assert.NotEmpty(t, args)
	assert.Equal(t, args,
		[]string{"-q",
			"-lf", dhclientV4LeaseFilePathPrefix + "-eth1.leases",
			"-pf", dhclientV4LeasePIDFilePathPrefix + "-eth1.pid",
			"eth1"})
}

func TestSetupNamespaceClosureRunFailsOnDHClientV4CommandCombinedOutputError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, mockExec, _ := setup(t)
	defer ctrl.Finish()

	mockCmd := mock_execwrapper.NewMockCmd(ctrl)
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(mockENILink).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, route.Gw.String(), eniIPV4Gateway)
		}).Return(nil),
		mockExec.EXPECT().Command(dhclientExecutableName,
			"-q",
			"-lf", dhclientV4LeaseFilePathPrefix+"-"+deviceName+".leases",
			"-pf", dhclientV4LeasePIDFilePathPrefix+"-"+deviceName+".pid",
			"eth1").Return(mockCmd),
		mockCmd.EXPECT().CombinedOutput().Return([]byte{0}, errors.New("error")),
	)
	closure, err := newSetupNamespaceClosureContext(mockNetLink, mockExec, deviceName, eniIPV4CIDRBlock, "", eniIPV4Gateway, "")
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestSetupNamespaceClosureRunFailsOnIPV6RouteAddError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, mockExec, _ := setup(t)
	defer ctrl.Finish()

	mockCmd := mock_execwrapper.NewMockCmd(ctrl)
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	ipv6Address := &netlink.Addr{}
	eniLinkIndex := 1
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().ParseAddr(eniIPV6CIDRBlock).Return(ipv6Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv6Address).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(mockENILink).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, route.Gw.String(), eniIPV4Gateway)
		}).Return(nil),
		mockExec.EXPECT().Command(dhclientExecutableName,
			"-q",
			"-lf", dhclientV4LeaseFilePathPrefix+"-"+deviceName+".leases",
			"-pf", dhclientV4LeasePIDFilePathPrefix+"-"+deviceName+".pid",
			"eth1").Return(mockCmd),
		mockCmd.EXPECT().CombinedOutput().Return([]byte{0}, nil),
		mockENILink.EXPECT().Attrs().Return(&netlink.LinkAttrs{Index: eniLinkIndex}),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, route.Gw.String(), eniIPV6Gateway)
			assert.Equal(t, route.LinkIndex, eniLinkIndex)
		}).Return(errors.New("error")),
	)
	closure, err := newSetupNamespaceClosureContext(mockNetLink, mockExec, deviceName, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway)
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestGetDHClientV6Args(t *testing.T) {
	args := constructDHClientV6Args("eth1")
	assert.NotEmpty(t, args)
	assert.Equal(t, args,
		[]string{"-q",
			"-6",
			"-lf", dhclientV6LeaseFilePathPrefix + "-eth1.leases",
			"-pf", dhclientV6LeasePIDFilePathPrefix + "-eth1.pid",
			"eth1"})
}

func TestSetupNamespaceClosureRunFailsOnDHClientV6CommandCombinedOutputError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, mockExec, _ := setup(t)
	defer ctrl.Finish()

	mockCmd := mock_execwrapper.NewMockCmd(ctrl)
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	ipv6Address := &netlink.Addr{}
	eniLinkIndex := 1
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().ParseAddr(eniIPV6CIDRBlock).Return(ipv6Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv6Address).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(mockENILink).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, route.Gw.String(), eniIPV4Gateway)
		}).Return(nil),
		mockExec.EXPECT().Command(dhclientExecutableName,
			"-q",
			"-lf", dhclientV4LeaseFilePathPrefix+"-"+deviceName+".leases",
			"-pf", dhclientV4LeasePIDFilePathPrefix+"-"+deviceName+".pid",
			"eth1").Return(mockCmd),
		mockCmd.EXPECT().CombinedOutput().Return([]byte{0}, nil),
		mockENILink.EXPECT().Attrs().Return(&netlink.LinkAttrs{Index: eniLinkIndex}),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, route.Gw.String(), eniIPV6Gateway)
			assert.Equal(t, route.LinkIndex, eniLinkIndex)
		}).Return(nil),
		mockExec.EXPECT().Command(dhclientExecutableName,
			"-q",
			"-6",
			"-lf", dhclientV6LeaseFilePathPrefix+"-"+deviceName+".leases",
			"-pf", dhclientV6LeasePIDFilePathPrefix+"-"+deviceName+".pid",
			"eth1").Return(mockCmd),
		mockCmd.EXPECT().CombinedOutput().Return([]byte{0}, errors.New("error")),
	)
	closure, err := newSetupNamespaceClosureContext(mockNetLink, mockExec, deviceName, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway)
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestSetupNamespaceClosureRunNoIPV6(t *testing.T) {
	ctrl, _, _, _, mockNetLink, mockExec, _ := setup(t)
	defer ctrl.Finish()

	mockCmd := mock_execwrapper.NewMockCmd(ctrl)
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(mockENILink).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, route.Gw.String(), eniIPV4Gateway)
		}).Return(nil),
		mockExec.EXPECT().Command(dhclientExecutableName,
			"-q",
			"-lf", dhclientV4LeaseFilePathPrefix+"-"+deviceName+".leases",
			"-pf", dhclientV4LeasePIDFilePathPrefix+"-"+deviceName+".pid",
			"eth1").Return(mockCmd),
		mockCmd.EXPECT().CombinedOutput().Return([]byte{0}, nil),
	)
	closure, err := newSetupNamespaceClosureContext(mockNetLink, mockExec, deviceName, eniIPV4CIDRBlock, "", eniIPV4Gateway, "")
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.NoError(t, err)
}

func TestSetupNamespaceClosureRun(t *testing.T) {
	ctrl, _, _, _, mockNetLink, mockExec, _ := setup(t)
	defer ctrl.Finish()

	mockCmd := mock_execwrapper.NewMockCmd(ctrl)
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockENILink := mock_netlink.NewMockLink(ctrl)
	ipv4Address := &netlink.Addr{}
	ipv6Address := &netlink.Addr{}
	eniLinkIndex := 1
	gomock.InOrder(
		mockNetLink.EXPECT().ParseAddr(eniIPV4CIDRBlock).Return(ipv4Address, nil),
		mockNetLink.EXPECT().ParseAddr(eniIPV6CIDRBlock).Return(ipv6Address, nil),
		mockNetLink.EXPECT().LinkByName(deviceName).Return(mockENILink, nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv4Address).Return(nil),
		mockNetLink.EXPECT().AddrAdd(mockENILink, ipv6Address).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(mockENILink).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, route.Gw.String(), eniIPV4Gateway)
		}).Return(nil),
		mockExec.EXPECT().Command(dhclientExecutableName,
			"-q",
			"-lf", dhclientV4LeaseFilePathPrefix+"-"+deviceName+".leases",
			"-pf", dhclientV4LeasePIDFilePathPrefix+"-"+deviceName+".pid",
			"eth1").Return(mockCmd),
		mockCmd.EXPECT().CombinedOutput().Return([]byte{0}, nil),
		mockENILink.EXPECT().Attrs().Return(&netlink.LinkAttrs{Index: eniLinkIndex}),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, route.Gw.String(), eniIPV6Gateway)
			assert.Equal(t, route.LinkIndex, eniLinkIndex)
		}).Return(nil),
		mockExec.EXPECT().Command(dhclientExecutableName,
			"-q",
			"-6",
			"-lf", dhclientV6LeaseFilePathPrefix+"-"+deviceName+".leases",
			"-pf", dhclientV6LeasePIDFilePathPrefix+"-"+deviceName+".pid",
			"eth1").Return(mockCmd),
		mockCmd.EXPECT().CombinedOutput().Return([]byte{0}, nil),
	)
	closure, err := newSetupNamespaceClosureContext(mockNetLink, mockExec, deviceName, eniIPV4CIDRBlock, eniIPV6CIDRBlock, eniIPV4Gateway, eniIPV6Gateway)
	assert.NoError(t, err)
	assert.NotNil(t, closure)
	err = closure.run(mockNetNS)
	assert.NoError(t, err)
}

func TestGetLinkByHardwareAddressFailsOnListLinkError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, _, _ := setup(t)
	defer ctrl.Finish()

	hwAddress := net.HardwareAddr{}

	mockNetLink.EXPECT().LinkList().Return(nil, errors.New("error"))
	_, err := getLinkByHardwareAddress(mockNetLink, hwAddress)
	assert.Error(t, err)
}

func TestGetLinkByHardwareAddressFailsWhenLinkNotFound(t *testing.T) {
	ctrl, _, _, _, mockNetLink, _, _ := setup(t)
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
	ctrl, _, _, _, mockNetLink, _, _ := setup(t)
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

func TestNewTeardownNamespaceClosureFailsOnInvalidMAC(t *testing.T) {
	ctrl, _, mockIOUtil, _, mockNetLink, _, mockOS := setup(t)
	defer ctrl.Finish()

	_, err := newTeardownNamespaceClosureContext(mockNetLink, mockIOUtil, mockOS, invalidMACAddress, false,
		checkProcessStateInterval, maxProcessStopWaitDuration)
	assert.Error(t, err)
}

func TestNewTeardownNamespaceClosure(t *testing.T) {
	ctrl, _, mockIOUtil, _, mockNetLink, _, mockOS := setup(t)
	defer ctrl.Finish()

	closure, err := newTeardownNamespaceClosureContext(mockNetLink, mockIOUtil, mockOS, eniMACAddress, false,
		checkProcessStateInterval, maxProcessStopWaitDuration)
	assert.NoError(t, err)
	assert.NotNil(t, closure)
}

func TestConstructDHClientLeasePIDFilePathIPV4(t *testing.T) {
	path := constructDHClientLeasePIDFilePathIPV4(deviceName)
	assert.Equal(t, path, dhclientV4LeasePIDFilePathPrefix+"-"+deviceName+".pid")
}

func TestConstructDHClientLeasePIDFilePathIPV6(t *testing.T) {
	path := constructDHClientLeasePIDFilePathIPV6(deviceName)
	assert.Equal(t, path, dhclientV6LeasePIDFilePathPrefix+"-"+deviceName+".pid")
}

func TestTearDownNamespaceClosureRunFailsWhenGetLinkByHardwareAddressReturnsError(t *testing.T) {
	ctrl, _, mockIOUtil, _, mockNetLink, _, mockOS := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	closure, err := newTeardownNamespaceClosureContext(mockNetLink, mockIOUtil, mockOS, eniMACAddress, false,
		checkProcessStateInterval, maxProcessStopWaitDuration)
	assert.NoError(t, err)
	assert.NotNil(t, closure)

	mockNetLink.EXPECT().LinkList().Return(nil, errors.New("error"))
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestIsProcessFinishedReturnsErrorWhenSignalProcessFails(t *testing.T) {
	ctrl, _, _, _, _, _, mockOS := setup(t)
	defer ctrl.Finish()

	mockDHClientProcess := mock_oswrapper.NewMockOSProcess(ctrl)
	gomock.InOrder(
		// Ensure that isProcessFinished errors out by failing the
		// Signal(0) call
		mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientProcess, nil),
		mockDHClientProcess.EXPECT().Signal(syscall.Signal(0)).Return(errors.New("error")),
	)

	ok, err := isProcessFinished(mockOS, dhclientV4PID)
	assert.Error(t, err)
	assert.False(t, ok)
}

func TestIsProcessFinishedReturnsFalseWhenSignalProcessSucceeds(t *testing.T) {
	ctrl, _, _, _, _, _, mockOS := setup(t)
	defer ctrl.Finish()

	mockDHClientProcess := mock_oswrapper.NewMockOSProcess(ctrl)
	gomock.InOrder(
		// Mock a successful execution of the Signal(0) call, thus mocking
		// that the process is executing
		mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientProcess, nil),
		mockDHClientProcess.EXPECT().Signal(syscall.Signal(0)).Return(nil),
	)

	ok, err := isProcessFinished(mockOS, dhclientV4PID)
	assert.NoError(t, err)
	assert.False(t, ok)
}

func TestIsProcessFinishedReturnsTrueWhenSignalProcessFailsWithProcessFinishedError(t *testing.T) {
	ctrl, _, _, _, _, _, mockOS := setup(t)
	defer ctrl.Finish()

	mockDHClientProcess := mock_oswrapper.NewMockOSProcess(ctrl)
	gomock.InOrder(
		// Signal(0) fails with the error message that inidcates that the
		// process has finished it's execution
		mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientProcess, nil),
		mockDHClientProcess.EXPECT().Signal(syscall.Signal(0)).Return(errors.New(processFinishedErrorMessage)),
	)

	ok, err := isProcessFinished(mockOS, dhclientV4PID)
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestWaitForStopReturnsNoErrorWhenProcessIsFinished(t *testing.T) {
	ctrl, _, _, _, _, _, mockOS := setup(t)
	defer ctrl.Finish()

	ctx, cancel := context.WithCancel(context.TODO())
	mockDHClientProcess := mock_oswrapper.NewMockOSProcess(ctrl)
	gomock.InOrder(
		mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientProcess, nil),
		mockDHClientProcess.EXPECT().Signal(syscall.Signal(0)).Return(errors.New(processFinishedErrorMessage)),
	)
	err := waitForProcesToFinish(ctx, cancel, mockOS, time.Microsecond, dhclientV4PID)
	assert.NoError(t, err)
}

func TestWaitForStopWaitsForDurationWhenSignallingProcessFails(t *testing.T) {
	ctrl, _, _, _, _, _, mockOS := setup(t)
	defer ctrl.Finish()

	ctx, cancel := context.WithCancel(context.TODO())
	mockDHClientProcess := mock_oswrapper.NewMockOSProcess(ctrl)
	gomock.InOrder(
		// Both invocations of isProcessFinished return error, however the
		// second invocation causes the context being cancelled, thus
		// simulating a context timing out
		mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientProcess, nil),
		mockDHClientProcess.EXPECT().Signal(syscall.Signal(0)).Return(errors.New("error")),
		mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientProcess, nil),
		mockDHClientProcess.EXPECT().Signal(syscall.Signal(0)).Do(func(_ syscall.Signal) {
			cancel()
		}).Return(nil),
	)
	err := waitForProcesToFinish(ctx, cancel, mockOS, time.Microsecond, dhclientV4PID)
	assert.Error(t, err)
}

func TestWaitForStopWaitsForDuration(t *testing.T) {
	ctrl, _, _, _, _, _, mockOS := setup(t)
	defer ctrl.Finish()

	ctx, cancel := context.WithCancel(context.TODO())
	mockDHClientProcess := mock_oswrapper.NewMockOSProcess(ctrl)
	gomock.InOrder(
		// Both invocations of isProcessFinished return no error, however the
		// second invocation causes the context being cancelled, thus
		// simulating a context timing out
		mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientProcess, nil),
		mockDHClientProcess.EXPECT().Signal(syscall.Signal(0)).Return(nil),
		mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientProcess, nil),
		mockDHClientProcess.EXPECT().Signal(syscall.Signal(0)).Do(func(_ syscall.Signal) {
			cancel()
		}).Return(nil),
	)
	err := waitForProcesToFinish(ctx, cancel, mockOS, time.Microsecond, dhclientV4PID)
	assert.Error(t, err)
}

func TestStopProcessFailsWhenUnableToSendSIGTERM(t *testing.T) {
	ctrl, _, _, _, _, _, mockOS := setup(t)
	defer ctrl.Finish()

	mockDHClientProcess := mock_oswrapper.NewMockOSProcess(ctrl)
	gomock.InOrder(
		mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientProcess, nil),
		mockDHClientProcess.EXPECT().Signal(syscall.SIGTERM).Return(errors.New("error")),
	)
	err := stopProcess(mockOS, dhclientV4PID, time.Microsecond, 10*time.Minute)
	assert.Error(t, err)
}

func TestStopProcessKillsProcessWhenWaitTimesout(t *testing.T) {
	ctrl, _, _, _, _, _, mockOS := setup(t)
	defer ctrl.Finish()

	mockDHClientProcess := mock_oswrapper.NewMockOSProcess(ctrl)
	gomock.InOrder(
		mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientProcess, nil),
		mockDHClientProcess.EXPECT().Signal(syscall.SIGTERM).Return(nil),
	)

	// These are unordered because the ticker might or might not kick in
	// during test execution. We have that code path covered in previous
	// tests anyway. The important thing is that Signal(SIGKILL) is invoked
	mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientProcess, nil).AnyTimes()
	mockDHClientProcess.EXPECT().Signal(syscall.Signal(0)).Return(nil).AnyTimes()

	mockDHClientProcess.EXPECT().Signal(syscall.SIGKILL).Return(nil)
	err := stopProcess(mockOS, dhclientV4PID, time.Microsecond, 10*time.Microsecond)
	assert.NoError(t, err)
}

func TestStopProcessReturnsErrorWhenSIGKILLSignalFails(t *testing.T) {
	ctrl, _, _, _, _, _, mockOS := setup(t)
	defer ctrl.Finish()

	mockDHClientProcess := mock_oswrapper.NewMockOSProcess(ctrl)
	gomock.InOrder(
		mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientProcess, nil),
		mockDHClientProcess.EXPECT().Signal(syscall.SIGTERM).Return(nil),
	)

	// These are unordered because the ticker might or might not kick in
	// during test execution. We have that code path covered in previous
	// tests anyway. The important thing is that Signal(SIGKILL) is invoked
	mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientProcess, nil).AnyTimes()
	mockDHClientProcess.EXPECT().Signal(syscall.Signal(0)).Return(nil).AnyTimes()

	mockDHClientProcess.EXPECT().Signal(syscall.SIGKILL).Return(errors.New("error"))
	err := stopProcess(mockOS, dhclientV4PID, time.Microsecond, 10*time.Microsecond)
	assert.Error(t, err)
}

func TestStopDHClientFailsWhenReadFileReturnsError(t *testing.T) {
	ctrl, _, mockIOUtil, _, mockNetLink, _, mockOS := setup(t)
	defer ctrl.Finish()

	closure, err := newTeardownNamespaceClosureContext(mockNetLink, mockIOUtil, mockOS, eniMACAddress, false,
		checkProcessStateInterval, maxProcessStopWaitDuration)
	assert.NoError(t, err)
	assert.NotNil(t, closure)

	pidFilePath := "1123.pid"
	gomock.InOrder(
		mockIOUtil.EXPECT().ReadFile(pidFilePath).Return(nil, errors.New("error")),
	)
	err = closure.stopDHClient(pidFilePath)
	assert.Error(t, err)
}

func TestStopDHClientFailsWhenReadFileReturnsInvalidPID(t *testing.T) {
	ctrl, _, mockIOUtil, _, mockNetLink, _, mockOS := setup(t)
	defer ctrl.Finish()

	closure, err := newTeardownNamespaceClosureContext(mockNetLink, mockIOUtil, mockOS, eniMACAddress, false,
		checkProcessStateInterval, maxProcessStopWaitDuration)
	assert.NoError(t, err)
	assert.NotNil(t, closure)

	pidFilePath := "1123.pid"
	gomock.InOrder(
		mockIOUtil.EXPECT().ReadFile(pidFilePath).Return([]byte(invalidDHClientPIDFieContents), nil),
	)
	err = closure.stopDHClient(pidFilePath)
	assert.Error(t, err)
}

func TestStopDHClientFailsWhenDHClientProcessNotFound(t *testing.T) {
	ctrl, _, mockIOUtil, _, mockNetLink, _, mockOS := setup(t)
	defer ctrl.Finish()

	closure, err := newTeardownNamespaceClosureContext(mockNetLink, mockIOUtil, mockOS, eniMACAddress, false,
		checkProcessStateInterval, maxProcessStopWaitDuration)
	assert.NoError(t, err)
	assert.NotNil(t, closure)

	pidFilePath := "1123.pid"
	gomock.InOrder(
		mockIOUtil.EXPECT().ReadFile(pidFilePath).Return([]byte(dhclientV4PIDFileContents), nil),
		mockOS.EXPECT().FindProcess(dhclientV4PID).Return(nil, errors.New("error")),
	)
	err = closure.stopDHClient(pidFilePath)
	assert.Error(t, err)
}

func TestStopDHClientRunFailsWhenDHClientProcessCannotBeKilled(t *testing.T) {
	ctrl, _, mockIOUtil, _, mockNetLink, _, mockOS := setup(t)
	defer ctrl.Finish()

	mockDHClientProcess := mock_oswrapper.NewMockOSProcess(ctrl)
	closure, err := newTeardownNamespaceClosureContext(mockNetLink, mockIOUtil, mockOS, eniMACAddress, false,
		time.Microsecond, 10*time.Microsecond)
	assert.NoError(t, err)
	assert.NotNil(t, closure)

	pidFilePath := "1123.pid"
	gomock.InOrder(
		mockIOUtil.EXPECT().ReadFile(pidFilePath).Return([]byte(dhclientV4PIDFileContents), nil),
		mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientProcess, nil),
		mockDHClientProcess.EXPECT().Signal(syscall.SIGTERM).Return(nil),
	)

	// These are unordered because TODO
	mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientProcess, nil).AnyTimes()
	mockDHClientProcess.EXPECT().Signal(syscall.Signal(0)).Return(nil).AnyTimes()

	mockDHClientProcess.EXPECT().Signal(syscall.SIGKILL).Return(errors.New("error"))
	// These are unordered because TODO
	err = closure.stopDHClient(pidFilePath)
	assert.Error(t, err)
}

func TestTearDownNamespaceClosureRunFailsWhenStopDHClientV4Fails(t *testing.T) {
	ctrl, _, mockIOUtil, _, mockNetLink, _, mockOS := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	eth1 := mock_netlink.NewMockLink(ctrl)
	mockDHClientProcess := mock_oswrapper.NewMockOSProcess(ctrl)
	closure, err := newTeardownNamespaceClosureContext(mockNetLink, mockIOUtil, mockOS, eniMACAddress, true,
		checkProcessStateInterval, maxProcessStopWaitDuration)
	assert.NoError(t, err)
	assert.NotNil(t, closure)

	eth1Address, err := net.ParseMAC(eniMACAddress)
	assert.NoError(t, err)

	gomock.InOrder(
		mockNetLink.EXPECT().LinkList().Return([]netlink.Link{eth1}, nil),
		eth1.EXPECT().Attrs().Return(&netlink.LinkAttrs{HardwareAddr: eth1Address}),
		eth1.EXPECT().Attrs().Return(&netlink.LinkAttrs{Name: deviceName}),
		mockIOUtil.EXPECT().ReadFile(dhclientV4LeasePIDFilePathPrefix+"-"+deviceName+".pid").Return([]byte(dhclientV4PIDFileContents), nil),
		mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientProcess, nil),
		mockDHClientProcess.EXPECT().Signal(syscall.SIGTERM).Return(errors.New("")),
	)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestTearDownNamespaceClosureRunFailsWhenStopDHClientV6Fails(t *testing.T) {
	ctrl, _, mockIOUtil, _, mockNetLink, _, mockOS := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	eth1 := mock_netlink.NewMockLink(ctrl)
	mockDHClientV4Process := mock_oswrapper.NewMockOSProcess(ctrl)
	mockDHClientV6Process := mock_oswrapper.NewMockOSProcess(ctrl)
	closure, err := newTeardownNamespaceClosureContext(mockNetLink, mockIOUtil, mockOS, eniMACAddress, true,
		checkProcessStateInterval, maxProcessStopWaitDuration)
	assert.NoError(t, err)
	assert.NotNil(t, closure)

	eth1Address, err := net.ParseMAC(eniMACAddress)
	assert.NoError(t, err)

	gomock.InOrder(
		mockNetLink.EXPECT().LinkList().Return([]netlink.Link{eth1}, nil),
		eth1.EXPECT().Attrs().Return(&netlink.LinkAttrs{HardwareAddr: eth1Address}),
		eth1.EXPECT().Attrs().Return(&netlink.LinkAttrs{Name: deviceName}),
		// Read dhclient4 pid
		mockIOUtil.EXPECT().ReadFile(dhclientV4LeasePIDFilePathPrefix+"-"+deviceName+".pid").Return([]byte(dhclientV4PIDFileContents), nil),
		// Find process and send SIGTERM
		mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientV4Process, nil),
		mockDHClientV4Process.EXPECT().Signal(syscall.SIGTERM).Return(nil),
		// Sending it SIGNAL(0) returns the error that indicates that the
		// process has finished its execution
		mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientV4Process, nil),
		mockDHClientV4Process.EXPECT().Signal(syscall.Signal(0)).Return(errors.New(processFinishedErrorMessage)),
		// Read dhclient6 pid
		mockIOUtil.EXPECT().ReadFile(dhclientV6LeasePIDFilePathPrefix+"-"+deviceName+".pid").Return([]byte(dhclientV6PIDFileContents), nil),
		// Find process and send SIGTERM, and simulate an error for
		// the same
		mockOS.EXPECT().FindProcess(dhclientV6PID).Return(mockDHClientV6Process, nil),
		mockDHClientV6Process.EXPECT().Signal(syscall.SIGTERM).Return(errors.New("error")),
	)
	err = closure.run(mockNetNS)
	assert.Error(t, err)
}

func TestTearDownNamespaceClosureRunNoIPV6(t *testing.T) {
	ctrl, _, mockIOUtil, _, mockNetLink, _, mockOS := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	eth1 := mock_netlink.NewMockLink(ctrl)
	mockDHClientV4Process := mock_oswrapper.NewMockOSProcess(ctrl)
	closure, err := newTeardownNamespaceClosureContext(mockNetLink, mockIOUtil, mockOS, eniMACAddress, false,
		checkProcessStateInterval, maxProcessStopWaitDuration)
	assert.NoError(t, err)
	assert.NotNil(t, closure)

	eth1Address, err := net.ParseMAC(eniMACAddress)
	assert.NoError(t, err)

	gomock.InOrder(
		mockNetLink.EXPECT().LinkList().Return([]netlink.Link{eth1}, nil),
		eth1.EXPECT().Attrs().Return(&netlink.LinkAttrs{HardwareAddr: eth1Address}),
		eth1.EXPECT().Attrs().Return(&netlink.LinkAttrs{Name: deviceName}),
		// Read dhclient4 pid
		mockIOUtil.EXPECT().ReadFile(dhclientV4LeasePIDFilePathPrefix+"-"+deviceName+".pid").Return([]byte(dhclientV4PIDFileContents), nil),
		// Find process and send SIGTERM
		mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientV4Process, nil),
		mockDHClientV4Process.EXPECT().Signal(syscall.SIGTERM).Return(nil),
		// Sending it SIGNAL(0) returns the error that indicates that the
		// process has finished its execution
		mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientV4Process, nil),
		mockDHClientV4Process.EXPECT().Signal(syscall.Signal(0)).Return(errors.New(processFinishedErrorMessage)),
	)
	err = closure.run(mockNetNS)
	assert.NoError(t, err)
}

func TestTearDownNamespaceClosureRun(t *testing.T) {
	ctrl, _, mockIOUtil, _, mockNetLink, _, mockOS := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	eth1 := mock_netlink.NewMockLink(ctrl)
	mockDHClientV4Process := mock_oswrapper.NewMockOSProcess(ctrl)
	mockDHClientV6Process := mock_oswrapper.NewMockOSProcess(ctrl)
	closure, err := newTeardownNamespaceClosureContext(mockNetLink, mockIOUtil, mockOS, eniMACAddress, true,
		checkProcessStateInterval, maxProcessStopWaitDuration)
	assert.NoError(t, err)
	assert.NotNil(t, closure)

	eth1Address, err := net.ParseMAC(eniMACAddress)
	assert.NoError(t, err)

	gomock.InOrder(
		mockNetLink.EXPECT().LinkList().Return([]netlink.Link{eth1}, nil),
		eth1.EXPECT().Attrs().Return(&netlink.LinkAttrs{HardwareAddr: eth1Address}),
		eth1.EXPECT().Attrs().Return(&netlink.LinkAttrs{Name: deviceName}),
		// Read dhclient4 pid
		mockIOUtil.EXPECT().ReadFile(dhclientV4LeasePIDFilePathPrefix+"-"+deviceName+".pid").Return([]byte(dhclientV4PIDFileContents), nil),
		// Find process and send SIGTERM
		mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientV4Process, nil),
		mockDHClientV4Process.EXPECT().Signal(syscall.SIGTERM).Return(nil),
		// Sending it SIGNAL(0) returns the error that indicates that the
		// process has finished its execution
		mockOS.EXPECT().FindProcess(dhclientV4PID).Return(mockDHClientV4Process, nil),
		mockDHClientV4Process.EXPECT().Signal(syscall.Signal(0)).Return(errors.New(processFinishedErrorMessage)),
		// Read dhclient6 pid
		mockIOUtil.EXPECT().ReadFile(dhclientV6LeasePIDFilePathPrefix+"-"+deviceName+".pid").Return([]byte(dhclientV6PIDFileContents), nil),
		// Find process and send SIGTERM
		mockOS.EXPECT().FindProcess(dhclientV6PID).Return(mockDHClientV6Process, nil),
		mockDHClientV6Process.EXPECT().Signal(syscall.SIGTERM).Return(nil),
		// Sending it SIGNAL(0) returns the error that indicates that the
		// process has finished its execution
		mockOS.EXPECT().FindProcess(dhclientV6PID).Return(mockDHClientV6Process, nil),
		mockDHClientV6Process.EXPECT().Signal(syscall.Signal(0)).Return(errors.New(processFinishedErrorMessage)),
	)
	err = closure.run(mockNetNS)
	assert.NoError(t, err)
}

func TestTeardownContainerNamespaceFailsOnWithNetNSPathError(t *testing.T) {
	ctrl, _, _, _, mockNetLink, _, _ := setup(t)
	defer ctrl.Finish()

	engine := &engine{netLink: mockNetLink}
	err := engine.TeardownContainerNamespace("ns1", invalidMACAddress, false)
	assert.Error(t, err)
}

func TestTeardownContainerNamespaceFailsOnParseMACError(t *testing.T) {
	ctrl, _, _, mockNS, mockNetLink, _, _ := setup(t)
	defer ctrl.Finish()

	mockNS.EXPECT().WithNetNSPath("ns1", gomock.Any()).Return(errors.New("error"))

	engine := &engine{ns: mockNS, netLink: mockNetLink}
	err := engine.TeardownContainerNamespace("ns1", eniMACAddress, false)
	assert.Error(t, err)
}

func TestTeardownContainerNamespace(t *testing.T) {
	ctrl, _, _, mockNS, mockNetLink, _, _ := setup(t)
	defer ctrl.Finish()

	mockNS.EXPECT().WithNetNSPath("ns1", gomock.Any()).Return(nil)

	engine := &engine{ns: mockNS, netLink: mockNetLink}
	err := engine.TeardownContainerNamespace("ns1", eniMACAddress, false)
	assert.NoError(t, err)
}
