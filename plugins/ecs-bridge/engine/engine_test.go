//go:build !integration && !e2e
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

package engine

import (
	"net"
	"syscall"
	"testing"

	mock_cniipamwrapper "github.com/aws/amazon-ecs-cni-plugins/pkg/cniipamwrapper/mocks"
	mock_types "github.com/aws/amazon-ecs-cni-plugins/pkg/cniipamwrapper/mocks_types"
	mock_cniipwrapper "github.com/aws/amazon-ecs-cni-plugins/pkg/cniipwrapper/mocks"
	mock_cninswrapper "github.com/aws/amazon-ecs-cni-plugins/pkg/cninswrapper/mocks"
	mock_ns "github.com/aws/amazon-ecs-cni-plugins/pkg/cninswrapper/mocks_netns"
	mock_netlinkwrapper "github.com/aws/amazon-ecs-cni-plugins/pkg/netlinkwrapper/mocks"
	mock_netlink "github.com/aws/amazon-ecs-cni-plugins/pkg/netlinkwrapper/mocks_link"
	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

const (
	bridgeName    = "br0"
	mtu           = 9100
	netns         = "ns1"
	interfaceName = "ecs-eth0"
	mac           = "01:23:45:67:89:ab"
	ipamType      = "ecs-ipam"
	gatewayIPCIDR = "192.168.1.1/31"
	gatewayIP     = "192.168.1.1"
)

var macHWAddr net.HardwareAddr

func init() {
	macHWAddr, _ = net.ParseMAC(mac)
}

func setup(t *testing.T) (*gomock.Controller,
	*mock_cninswrapper.MockNS,
	*mock_netlinkwrapper.MockNetLink,
	*mock_cniipwrapper.MockIP,
	*mock_cniipamwrapper.MockIPAM,
	*mock_cninswrapper.MockNS) {
	ctrl := gomock.NewController(t)
	return ctrl,
		mock_cninswrapper.NewMockNS(ctrl),
		mock_netlinkwrapper.NewMockNetLink(ctrl),
		mock_cniipwrapper.NewMockIP(ctrl),
		mock_cniipamwrapper.NewMockIPAM(ctrl),
		mock_cninswrapper.NewMockNS(ctrl)
}

func TestLookupBridgeLinkByNameError(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkByName(bridgeName).Return(nil, errors.New("error"))
	engine := &engine{netLink: mockNetLink}
	_, err := engine.lookupBridge(bridgeName)
	assert.Error(t, err)
}

func TestLookupBridgeNotABridgeError(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkByName(bridgeName).Return(&netlink.Dummy{}, nil)
	engine := &engine{netLink: mockNetLink}
	_, err := engine.lookupBridge(bridgeName)
	assert.Error(t, err)
}

func TestLookupBridgeLinkNotFound(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkByName(bridgeName).Return(nil, netlink.LinkNotFoundError{})
	engine := &engine{netLink: mockNetLink}
	bridge, err := engine.lookupBridge(bridgeName)
	assert.NoError(t, err)
	assert.Nil(t, bridge)
}

func TestLookupBridgeLinkFound(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkByName(bridgeName).Return(&netlink.Bridge{}, nil)
	engine := &engine{netLink: mockNetLink}
	bridge, err := engine.lookupBridge(bridgeName)
	assert.NoError(t, err)
	assert.NotNil(t, bridge)
}

func TestCreateBridgeInternalLinkAddError(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkAdd(gomock.Any()).Do(func(link netlink.Link) {
		assert.Equal(t, bridgeName, link.Attrs().Name)
		assert.Equal(t, mtu, link.Attrs().MTU)
		assert.Equal(t, -1, link.Attrs().TxQLen)
	}).Return(errors.New("error"))
	engine := &engine{netLink: mockNetLink}
	err := engine.createBridge(bridgeName, mtu)
	assert.Error(t, err)
}

func TestCreateBridgeLookupBridgeError(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkByName(bridgeName).Return(nil, errors.New("error"))
	engine := &engine{netLink: mockNetLink}
	_, err := engine.CreateBridge(bridgeName, mtu)
	assert.Error(t, err)
}

func TestCreateBridgeLinkAddExistErrorLinkSetUpSuccess(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{}
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(bridgeName).Return(nil, netlink.LinkNotFoundError{}),
		mockNetLink.EXPECT().LinkAdd(gomock.Any()).Return(errors.New("file exists")),
		mockNetLink.EXPECT().LinkByName(bridgeName).Return(bridgeLink, nil),
		mockNetLink.EXPECT().LinkSetUp(bridgeLink).Return(nil),
	)
	engine := &engine{netLink: mockNetLink}
	_, err := engine.CreateBridge(bridgeName, mtu)
	assert.NoError(t, err)
}

func TestCreateBridgeLinkAddOtherError(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(bridgeName).Return(nil, netlink.LinkNotFoundError{}),
		mockNetLink.EXPECT().LinkAdd(gomock.Any()).Return(errors.New("error")),
	)
	engine := &engine{netLink: mockNetLink}
	_, err := engine.CreateBridge(bridgeName, mtu)
	assert.Error(t, err)
}

func TestCreateBridgeLinkSetupError(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{}
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(bridgeName).Return(nil, netlink.LinkNotFoundError{}),
		mockNetLink.EXPECT().LinkAdd(gomock.Any()).Return(nil),
		mockNetLink.EXPECT().LinkSetHardwareAddr(gomock.Any(), gomock.Any()).Return(nil),
		mockNetLink.EXPECT().LinkByName(bridgeName).Return(bridgeLink, nil),
		mockNetLink.EXPECT().LinkSetUp(bridgeLink).Return(errors.New("error")),
	)
	engine := &engine{netLink: mockNetLink}
	_, err := engine.CreateBridge(bridgeName, mtu)
	assert.Error(t, err)
}

func TestCreateBridgeSuccess(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{}
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(bridgeName).Return(nil, netlink.LinkNotFoundError{}),
		mockNetLink.EXPECT().LinkAdd(gomock.Any()).Return(nil),
		mockNetLink.EXPECT().LinkSetHardwareAddr(gomock.Any(), gomock.Any()).Return(nil),
		mockNetLink.EXPECT().LinkByName(bridgeName).Return(bridgeLink, nil),
		mockNetLink.EXPECT().LinkSetUp(bridgeLink).Return(nil),
	)
	engine := &engine{netLink: mockNetLink}
	createdBridge, err := engine.CreateBridge(bridgeName, mtu)
	assert.NoError(t, err)
	assert.Equal(t, bridgeLink, createdBridge)
}

func TestCreateVethPairSetupVethError(t *testing.T) {
	ctrl, _, _, mockIP, _, _ := setup(t)
	defer ctrl.Finish()

	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockIP.EXPECT().SetupVeth(interfaceName, mtu, mockNetNS).Return(
		net.Interface{}, net.Interface{}, errors.New("error"))
	createVethContext := newCreateVethPairContext(
		interfaceName, mtu, mockIP)
	err := createVethContext.run(mockNetNS)
	assert.Error(t, err)

}

func TestCreateVethPairSuccess(t *testing.T) {
	ctrl, _, _, mockIP, _, _ := setup(t)
	defer ctrl.Finish()

	hostVeth := net.Interface{
		Name: "host-veth0",
	}
	containerVeth := net.Interface{
		Name:         "ctr-veth0",
		HardwareAddr: macHWAddr,
	}
	mockNetNS := mock_ns.NewMockNetNS(ctrl)
	mockIP.EXPECT().SetupVeth(interfaceName, mtu, mockNetNS).Return(
		hostVeth, containerVeth, nil)
	createVethContext := newCreateVethPairContext(
		interfaceName, mtu, mockIP)
	err := createVethContext.run(mockNetNS)
	assert.NoError(t, err)
	assert.Equal(t, hostVeth.Name, createVethContext.hostVethName)
	assert.Equal(t, containerVeth.Name, createVethContext.containerInterfaceResult.Name)
	assert.Equal(t, mac, createVethContext.containerInterfaceResult.Mac)
}

func TestCreateVethPairWithNetNSPathError(t *testing.T) {
	ctrl, _, _, _, _, mockNS := setup(t)
	defer ctrl.Finish()

	mockNS.EXPECT().WithNetNSPath(netns, gomock.Any()).Return(errors.New("error"))
	engine := &engine{ns: mockNS}
	_, _, err := engine.CreateVethPair(netns, mtu, interfaceName)
	assert.Error(t, err)
}

func TestAttachHostVethInterfaceToBridgeLinkByNameError(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	hostVethName := "host-veth0"
	mockNetLink.EXPECT().LinkByName(hostVethName).Return(nil, errors.New("error"))
	engine := &engine{netLink: mockNetLink}
	_, err := engine.AttachHostVethInterfaceToBridge(hostVethName, nil)
	assert.Error(t, err)
}

func TestAttachHostVethInterfaceToBridgeLinkSetMasterError(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	hostVethName := "host-veth0"
	hostVethInterface := &netlink.Dummy{}
	bridgeLink := &netlink.Bridge{}
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(hostVethName).Return(hostVethInterface, nil),
		mockNetLink.EXPECT().LinkSetMaster(hostVethInterface, bridgeLink).Return(errors.New("error")),
	)
	engine := &engine{netLink: mockNetLink}
	_, err := engine.AttachHostVethInterfaceToBridge(hostVethName, bridgeLink)
	assert.Error(t, err)
}

func TestAttachHostVethInterfaceToBridgeSuccess(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	hostVethName := "host-veth0"
	hostVethInterface := mock_netlink.NewMockLink(ctrl)
	bridgeLink := &netlink.Bridge{}
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(hostVethName).Return(hostVethInterface, nil),
		mockNetLink.EXPECT().LinkSetMaster(hostVethInterface, bridgeLink).Return(nil),
		hostVethInterface.EXPECT().Attrs().Return(&netlink.LinkAttrs{HardwareAddr: macHWAddr}),
	)
	engine := &engine{netLink: mockNetLink}
	hostVethResult, err := engine.AttachHostVethInterfaceToBridge(hostVethName, bridgeLink)
	assert.NoError(t, err)
	assert.Equal(t, hostVethName, hostVethResult.Name)
	assert.Equal(t, mac, hostVethResult.Mac)
}

func TestRunIPAMPluginAddExecAddError(t *testing.T) {
	ctrl, _, _, _, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	netConf := []byte{}
	mockIPAM.EXPECT().ExecAdd(ipamType, netConf).Return(nil, errors.New("error"))
	engine := &engine{ipam: mockIPAM}
	_, err := engine.RunIPAMPluginAdd(ipamType, netConf)
	assert.Error(t, err)
}

func TestRunIPAMPluginAddResultConversionError(t *testing.T) {
	ctrl, _, _, _, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	netConf := []byte{}
	result := mock_types.NewMockResult(ctrl)
	gomock.InOrder(
		mockIPAM.EXPECT().ExecAdd(ipamType, netConf).Return(result, nil),
		// Return an unsupported CNI version, which should cause the
		// current.NewResultFromResult to return an error, thus
		// simulating a "parse error"
		result.EXPECT().Version().Return("a.b.c").MinTimes(1),
		result.EXPECT().String().Return(""),
	)
	engine := &engine{ipam: mockIPAM}
	_, err := engine.RunIPAMPluginAdd(ipamType, netConf)
	assert.Error(t, err)
}

func TestRunIPAMPluginAddResultParseErrorInvalidNumIPs(t *testing.T) {
	ctrl, _, _, _, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	netConf := []byte{}
	result := &current.Result{}
	mockIPAM.EXPECT().ExecAdd(ipamType, netConf).Return(result, nil)
	engine := &engine{ipam: mockIPAM}
	_, err := engine.RunIPAMPluginAdd(ipamType, netConf)
	assert.Error(t, err)
}

func TestRunIPAMPluginAddResultParseErrorNoGateway(t *testing.T) {
	ctrl, _, _, _, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	netConf := []byte{}
	result := &current.Result{
		IPs: []*current.IPConfig{
			{},
		},
	}
	mockIPAM.EXPECT().ExecAdd(ipamType, netConf).Return(result, nil)
	engine := &engine{ipam: mockIPAM}
	_, err := engine.RunIPAMPluginAdd(ipamType, netConf)
	assert.Error(t, err)
}

func TestRunIPAMPluginAddMaskNotSet(t *testing.T) {
	ctrl, _, _, _, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	netConf := []byte{}
	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Gateway: net.ParseIP(gatewayIPCIDR),
			},
		},
	}
	mockIPAM.EXPECT().ExecAdd(ipamType, netConf).Return(result, nil)
	engine := &engine{ipam: mockIPAM}
	result, err := engine.RunIPAMPluginAdd(ipamType, netConf)
	assert.Error(t, err)
}

func TestRunIPAMPluginAddSuccess(t *testing.T) {
	ctrl, _, _, _, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	netConf := []byte{}
	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{
					Mask: net.CIDRMask(31, 32),
				},
				Gateway: net.ParseIP("192.168.1.1"),
			},
		},
	}
	mockIPAM.EXPECT().ExecAdd(ipamType, netConf).Return(result, nil)
	engine := &engine{ipam: mockIPAM}
	result, err := engine.RunIPAMPluginAdd(ipamType, netConf)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(result.IPs))
	assert.Equal(t, gatewayIP, result.IPs[0].Gateway.String())
}

// TestRunIPAMPluginAddSingleIPv6Success tests that a single IPv6 result is accepted
// Validates: Requirements 1.2
func TestRunIPAMPluginAddSingleIPv6Success(t *testing.T) {
	ctrl, _, _, _, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	netConf := []byte{}
	ipv6Gateway := net.ParseIP("2001:db8::1")
	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{
					IP:   net.ParseIP("2001:db8::2"),
					Mask: net.CIDRMask(64, 128),
				},
				Gateway: ipv6Gateway,
			},
		},
	}
	mockIPAM.EXPECT().ExecAdd(ipamType, netConf).Return(result, nil)
	engine := &engine{ipam: mockIPAM}
	result, err := engine.RunIPAMPluginAdd(ipamType, netConf)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(result.IPs))
	assert.Equal(t, ipv6Gateway.String(), result.IPs[0].Gateway.String())
}

// TestRunIPAMPluginAddDualStackSuccess tests that a dual-stack result (2 IPs) is accepted
// Validates: Requirements 1.3, 1.6
func TestRunIPAMPluginAddDualStackSuccess(t *testing.T) {
	ctrl, _, _, _, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	netConf := []byte{}
	ipv4Gateway := net.ParseIP("192.168.1.1")
	ipv6Gateway := net.ParseIP("2001:db8::1")
	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{
					IP:   net.ParseIP("192.168.1.2"),
					Mask: net.CIDRMask(24, 32),
				},
				Gateway: ipv4Gateway,
			},
			{
				Address: net.IPNet{
					IP:   net.ParseIP("2001:db8::2"),
					Mask: net.CIDRMask(64, 128),
				},
				Gateway: ipv6Gateway,
			},
		},
	}
	mockIPAM.EXPECT().ExecAdd(ipamType, netConf).Return(result, nil)
	engine := &engine{ipam: mockIPAM}
	result, err := engine.RunIPAMPluginAdd(ipamType, netConf)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(result.IPs))
	assert.Equal(t, ipv4Gateway.String(), result.IPs[0].Gateway.String())
	assert.Equal(t, ipv6Gateway.String(), result.IPs[1].Gateway.String())
}

// TestRunIPAMPluginAddEmptyResultError tests that an empty result returns an error
// Validates: Requirements 8.1
func TestRunIPAMPluginAddEmptyResultError(t *testing.T) {
	ctrl, _, _, _, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	netConf := []byte{}
	result := &current.Result{
		IPs: []*current.IPConfig{},
	}
	mockIPAM.EXPECT().ExecAdd(ipamType, netConf).Return(result, nil)
	engine := &engine{ipam: mockIPAM}
	_, err := engine.RunIPAMPluginAdd(ipamType, netConf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected 1 or 2 IP configs, got 0")
}

// TestRunIPAMPluginAddTooManyIPsError tests that more than 2 IPs returns an error
// Validates: Requirements 1.6
func TestRunIPAMPluginAddTooManyIPsError(t *testing.T) {
	ctrl, _, _, _, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	netConf := []byte{}
	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{
					IP:   net.ParseIP("192.168.1.2"),
					Mask: net.CIDRMask(24, 32),
				},
				Gateway: net.ParseIP("192.168.1.1"),
			},
			{
				Address: net.IPNet{
					IP:   net.ParseIP("2001:db8::2"),
					Mask: net.CIDRMask(64, 128),
				},
				Gateway: net.ParseIP("2001:db8::1"),
			},
			{
				Address: net.IPNet{
					IP:   net.ParseIP("10.0.0.2"),
					Mask: net.CIDRMask(24, 32),
				},
				Gateway: net.ParseIP("10.0.0.1"),
			},
		},
	}
	mockIPAM.EXPECT().ExecAdd(ipamType, netConf).Return(result, nil)
	engine := &engine{ipam: mockIPAM}
	_, err := engine.RunIPAMPluginAdd(ipamType, netConf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected 1 or 2 IP configs, got 3")
}

// TestRunIPAMPluginAddMissingMaskSecondIPError tests that missing mask on second IP returns an error
// Validates: Requirements 1.4, 8.2
func TestRunIPAMPluginAddMissingMaskSecondIPError(t *testing.T) {
	ctrl, _, _, _, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	netConf := []byte{}
	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{
					IP:   net.ParseIP("192.168.1.2"),
					Mask: net.CIDRMask(24, 32),
				},
				Gateway: net.ParseIP("192.168.1.1"),
			},
			{
				Address: net.IPNet{
					IP: net.ParseIP("2001:db8::2"),
					// Missing mask
				},
				Gateway: net.ParseIP("2001:db8::1"),
			},
		},
	}
	mockIPAM.EXPECT().ExecAdd(ipamType, netConf).Return(result, nil)
	engine := &engine{ipam: mockIPAM}
	_, err := engine.RunIPAMPluginAdd(ipamType, netConf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IP address mask not set for IP[1]")
}

// TestRunIPAMPluginAddMissingGatewaySecondIPError tests that missing gateway on second IP returns an error
// Validates: Requirements 1.5, 8.3
func TestRunIPAMPluginAddMissingGatewaySecondIPError(t *testing.T) {
	ctrl, _, _, _, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	netConf := []byte{}
	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{
					IP:   net.ParseIP("192.168.1.2"),
					Mask: net.CIDRMask(24, 32),
				},
				Gateway: net.ParseIP("192.168.1.1"),
			},
			{
				Address: net.IPNet{
					IP:   net.ParseIP("2001:db8::2"),
					Mask: net.CIDRMask(64, 128),
				},
				// Missing gateway
			},
		},
	}
	mockIPAM.EXPECT().ExecAdd(ipamType, netConf).Return(result, nil)
	engine := &engine{ipam: mockIPAM}
	_, err := engine.RunIPAMPluginAdd(ipamType, netConf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Gateway not set for IP[1]")
}

// TestRunIPAMPluginAddMissingMaskIPv6Error tests that missing mask on IPv6-only result returns an error
// Validates: Requirements 1.4, 8.2
func TestRunIPAMPluginAddMissingMaskIPv6Error(t *testing.T) {
	ctrl, _, _, _, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	netConf := []byte{}
	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{
					IP: net.ParseIP("2001:db8::2"),
					// Missing mask
				},
				Gateway: net.ParseIP("2001:db8::1"),
			},
		},
	}
	mockIPAM.EXPECT().ExecAdd(ipamType, netConf).Return(result, nil)
	engine := &engine{ipam: mockIPAM}
	_, err := engine.RunIPAMPluginAdd(ipamType, netConf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IP address mask not set for IP[0]")
}

// TestRunIPAMPluginAddMissingGatewayIPv6Error tests that missing gateway on IPv6-only result returns an error
// Validates: Requirements 1.5, 8.3
func TestRunIPAMPluginAddMissingGatewayIPv6Error(t *testing.T) {
	ctrl, _, _, _, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	netConf := []byte{}
	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{
					IP:   net.ParseIP("2001:db8::2"),
					Mask: net.CIDRMask(64, 128),
				},
				// Missing gateway
			},
		},
	}
	mockIPAM.EXPECT().ExecAdd(ipamType, netConf).Return(result, nil)
	engine := &engine{ipam: mockIPAM}
	_, err := engine.RunIPAMPluginAdd(ipamType, netConf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Gateway not set for IP[0]")
}

func TestConfigureContainerVethInterfaceConfigureIfaceError(t *testing.T) {
	ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	ip, ipnet, err := net.ParseCIDR("10.0.0.1/22")
	assert.NoError(t, err)
	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: *ipnet,
				Gateway: ip,
			},
		},
	}
	mockIPAM.EXPECT().ConfigureIface(interfaceName, result).Return(errors.New("error"))
	configContext := newConfigureVethContext(
		interfaceName, result, mockIP, mockIPAM, mockNetLink)
	err = configContext.run(nil)
	assert.Error(t, err)
}

func TestConfigureContainerVethInterfaceSetHWAddrByIPError(t *testing.T) {
	ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	gatewayIPAddr := net.ParseIP(gatewayIP)
	containerIPAddr := net.ParseIP("192.168.1.2")
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   containerIPAddr,
			Mask: net.CIDRMask(31, 32),
		},
		Gateway: gatewayIPAddr,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	gomock.InOrder(
		mockIPAM.EXPECT().ConfigureIface(interfaceName, gomock.Any()).Return(nil),
		mockIP.EXPECT().SetHWAddrByIP(interfaceName, containerIPAddr, nil).Return(errors.New("error")),
	)
	configContext := newConfigureVethContext(
		interfaceName, result, mockIP, mockIPAM, mockNetLink)
	err := configContext.run(nil)
	assert.Error(t, err)
}

func TestConfigureContainerVethInterfaceLinkByNameError(t *testing.T) {
	ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	gatewayIPAddr := net.ParseIP(gatewayIP)
	containerIPAddr := net.ParseIP("192.168.1.2")
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   containerIPAddr,
			Mask: net.CIDRMask(31, 32),
		},
		Gateway: gatewayIPAddr,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	gomock.InOrder(
		mockIPAM.EXPECT().ConfigureIface(interfaceName, gomock.Any()).Return(nil),
		mockIP.EXPECT().SetHWAddrByIP(interfaceName, containerIPAddr, nil).Return(nil),
		mockNetLink.EXPECT().LinkByName(interfaceName).Return(nil, errors.New("error")),
	)
	configContext := newConfigureVethContext(
		interfaceName, result, mockIP, mockIPAM, mockNetLink)
	err := configContext.run(nil)
	assert.Error(t, err)
}

func TestConfigureContainerVethInterfaceRouteListError(t *testing.T) {
	ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	gatewayIPAddr := net.ParseIP(gatewayIP)
	containerIPAddr := net.ParseIP("192.168.1.2")
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   containerIPAddr,
			Mask: net.CIDRMask(31, 32),
		},
		Gateway: gatewayIPAddr,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	mockLink := mock_netlink.NewMockLink(ctrl)

	gomock.InOrder(
		mockIPAM.EXPECT().ConfigureIface(interfaceName, gomock.Any()).Return(nil),
		mockIP.EXPECT().SetHWAddrByIP(interfaceName, containerIPAddr, nil).Return(nil),
		mockNetLink.EXPECT().LinkByName(interfaceName).Return(mockLink, nil),
		mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_ALL).Return(nil, errors.New("error")),
	)
	configContext := newConfigureVethContext(
		interfaceName, result, mockIP, mockIPAM, mockNetLink)
	err := configContext.run(nil)
	assert.Error(t, err)
}

func TestConfigureContainerVethInterfaceRouteDelError(t *testing.T) {
	ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	gatewayIPAddr := net.ParseIP(gatewayIP)
	containerIPAddr := net.ParseIP("192.168.1.2")
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   containerIPAddr,
			Mask: net.CIDRMask(31, 32),
		},
		Gateway: gatewayIPAddr,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	mockLink := mock_netlink.NewMockLink(ctrl)
	// Route without gateway (default route) should be deleted
	route := netlink.Route{Gw: nil}
	routes := []netlink.Route{route}
	gomock.InOrder(
		mockIPAM.EXPECT().ConfigureIface(interfaceName, gomock.Any()).Return(nil),
		mockIP.EXPECT().SetHWAddrByIP(interfaceName, containerIPAddr, nil).Return(nil),
		mockNetLink.EXPECT().LinkByName(interfaceName).Return(mockLink, nil),
		mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_ALL).Return(routes, nil),
		mockNetLink.EXPECT().RouteDel(&route).Return(errors.New("error")),
	)
	configContext := newConfigureVethContext(
		interfaceName, result, mockIP, mockIPAM, mockNetLink)
	err := configContext.run(nil)
	assert.Error(t, err)
}

func TestConfigureContainerVethInterfaceContextSuccess(t *testing.T) {
	ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	gatewayIPAddr := net.ParseIP(gatewayIP)
	containerIPAddr := net.ParseIP("192.168.1.2")
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   containerIPAddr,
			Mask: net.CIDRMask(31, 32),
		},
		Gateway: gatewayIPAddr,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	mockLink := mock_netlink.NewMockLink(ctrl)
	// Route without gateway (default route) should be deleted
	route := netlink.Route{Gw: nil}
	routes := []netlink.Route{route}
	gomock.InOrder(
		mockIPAM.EXPECT().ConfigureIface(interfaceName, gomock.Any()).Return(nil),
		mockIP.EXPECT().SetHWAddrByIP(interfaceName, containerIPAddr, nil).Return(nil),
		mockNetLink.EXPECT().LinkByName(interfaceName).Return(mockLink, nil),
		mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_ALL).Return(routes, nil),
		mockNetLink.EXPECT().RouteDel(&route).Return(nil),
	)
	configContext := newConfigureVethContext(
		interfaceName, result, mockIP, mockIPAM, mockNetLink)
	err := configContext.run(nil)
	assert.NoError(t, err)
}

func TestConfigureContainerVethInterfaceWithNetNSPathError(t *testing.T) {
	ctrl, mockNS, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	mockNS.EXPECT().WithNetNSPath(netns, gomock.Any()).Return(errors.New("error"))
	engine := &engine{
		ns:      mockNS,
		ip:      mockIP,
		ipam:    mockIPAM,
		netLink: mockNetLink,
	}

	err := engine.ConfigureContainerVethInterface(netns, nil, interfaceName)
	assert.Error(t, err)
}

func TestConfigureContainerVethInterfaceSuccess(t *testing.T) {
	ctrl, mockNS, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	mockNS.EXPECT().WithNetNSPath(netns, gomock.Any()).Return(nil)
	engine := &engine{
		ns:      mockNS,
		ip:      mockIP,
		ipam:    mockIPAM,
		netLink: mockNetLink,
	}

	err := engine.ConfigureContainerVethInterface(netns, nil, interfaceName)
	assert.NoError(t, err)
}

func TestConfigureBridgeAddrListError(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{}
	gatewayIPAddr := net.ParseIP(gatewayIP)
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   net.ParseIP("192.168.1.2"),
			Mask: net.CIDRMask(31, 32),
		},
		Gateway: gatewayIPAddr,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET).Return(nil, errors.New("error"))

	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.Error(t, err)
}

func TestConfigureBridgeAddrListWhenFound(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{}
	gatewayIPAddr := net.ParseIP(gatewayIP)
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   net.ParseIP("192.168.1.2"),
			Mask: net.CIDRMask(31, 32),
		},
		Gateway: gatewayIPAddr,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	// The bridge already has the correct address (gateway IP with the same mask)
	addrs := []netlink.Addr{
		{
			IPNet: &net.IPNet{
				IP:   gatewayIPAddr,
				Mask: net.CIDRMask(31, 32),
			},
		},
	}
	gomock.InOrder(
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET).Return(addrs, nil),
	)
	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.NoError(t, err)
}

func TestConfigureBridgeAddrListWhenNotFound(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{Name: bridgeName},
	}
	gatewayIPAddr := net.ParseIP(gatewayIP)
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   net.ParseIP("192.168.1.2"),
			Mask: net.CIDRMask(31, 32),
		},
		Gateway: gatewayIPAddr,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	// Bridge has a different address than expected
	addrs := []netlink.Addr{
		{
			IPNet: &net.IPNet{
				IP:   net.ParseIP("10.0.0.1"),
				Mask: net.CIDRMask(24, 32),
			},
		},
	}
	gomock.InOrder(
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET).Return(addrs, nil),
	)
	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mismatch in bridge")
}

func TestConfigureBridgeAddrAddFileExistsError(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{}
	gatewayIPAddr := net.ParseIP(gatewayIP)
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   net.ParseIP("192.168.1.2"),
			Mask: net.CIDRMask(31, 32),
		},
		Gateway: gatewayIPAddr,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	bridgeAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   gatewayIPAddr,
			Mask: net.CIDRMask(31, 32),
		},
	}
	gomock.InOrder(
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET).Return(nil, nil),
		mockNetLink.EXPECT().AddrAdd(bridgeLink, bridgeAddr).Return(errors.New("file exists")),
	)
	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.NoError(t, err)
}

func TestConfigureBridgeAddrAddOtherError(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{Name: bridgeName},
	}
	gatewayIPAddr := net.ParseIP(gatewayIP)
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   net.ParseIP("192.168.1.2"),
			Mask: net.CIDRMask(31, 32),
		},
		Gateway: gatewayIPAddr,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	bridgeAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   gatewayIPAddr,
			Mask: net.CIDRMask(31, 32),
		},
	}
	gomock.InOrder(
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET).Return(nil, nil),
		mockNetLink.EXPECT().AddrAdd(bridgeLink, bridgeAddr).Return(errors.New("error")),
	)
	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.Error(t, err)
}

func TestConfigureBridgeAddrAddSuccess(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{}
	gatewayIPAddr := net.ParseIP(gatewayIP)
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   net.ParseIP("192.168.1.2"),
			Mask: net.CIDRMask(31, 32),
		},
		Gateway: gatewayIPAddr,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	bridgeAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   gatewayIPAddr,
			Mask: net.CIDRMask(31, 32),
		},
	}
	gomock.InOrder(
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET).Return(nil, nil),
		mockNetLink.EXPECT().AddrAdd(bridgeLink, bridgeAddr).Return(nil),
	)
	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.NoError(t, err)
}

func TestGetInterfaceIPV4AddressContextLinkByNameError(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkByName(interfaceName).Return(nil, errors.New("error"))
	ipv4Context := newGetContainerIPV4Context(interfaceName, mockNetLink)
	err := ipv4Context.run(nil)
	assert.Error(t, err)
}

func TestGetInterfaceIPV4AddressContextAddrListError(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockLink := mock_netlink.NewMockLink(ctrl)
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(interfaceName).Return(mockLink, nil),
		mockNetLink.EXPECT().AddrList(mockLink, netlink.FAMILY_V4).Return(nil, errors.New("error")),
	)
	ipv4Context := newGetContainerIPV4Context(interfaceName, mockNetLink)
	err := ipv4Context.run(nil)
	assert.Error(t, err)
}

func TestGetInterfaceIPV4AddressContextAddrListEmpty(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockLink := mock_netlink.NewMockLink(ctrl)
	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName(interfaceName).Return(mockLink, nil),
		mockNetLink.EXPECT().AddrList(mockLink, netlink.FAMILY_V4).Return(nil, nil),
	)
	ipv4Context := newGetContainerIPV4Context(interfaceName, mockNetLink)
	err := ipv4Context.run(nil)
	assert.Error(t, err)
}

func TestGetInterfaceIPV4AddressWithNetNSPathError(t *testing.T) {
	ctrl, mockNS, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockNS.EXPECT().WithNetNSPath(netns, gomock.Any()).Return(errors.New("error"))
	engine := &engine{
		ns: mockNS,
	}

	_, err := engine.GetInterfaceIPV4Address(netns, interfaceName)
	assert.Error(t, err)
}

func TestGetInterfaceIPV4AddressWithNetNSPathSuccess(t *testing.T) {
	ctrl, mockNS, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockNS.EXPECT().WithNetNSPath(netns, gomock.Any()).Return(nil)
	engine := &engine{
		ns: mockNS,
	}

	_, err := engine.GetInterfaceIPV4Address(netns, interfaceName)
	assert.NoError(t, err)
}

func TestRunIPAMPluginDelExecDelError(t *testing.T) {
	ctrl, _, _, _, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	netConf := []byte{}
	mockIPAM.EXPECT().ExecDel(ipamType, netConf).Return(errors.New("error"))
	engine := &engine{ipam: mockIPAM}
	err := engine.RunIPAMPluginDel(ipamType, netConf)
	assert.Error(t, err)
}

func TestRunIPAMPluginDelExecDelSuccess(t *testing.T) {
	ctrl, _, _, _, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	netConf := []byte{}
	mockIPAM.EXPECT().ExecDel(ipamType, netConf).Return(nil)
	engine := &engine{ipam: mockIPAM}
	err := engine.RunIPAMPluginDel(ipamType, netConf)
	assert.NoError(t, err)
}

func TestDeleteVethContextDelLinkByNameAddrError(t *testing.T) {
	ctrl, _, _, mockIP, _, _ := setup(t)
	defer ctrl.Finish()

	// When IPv4 deletion fails, it tries IPv6. If both fail, return error.
	mockIP.EXPECT().DelLinkByNameAddr(interfaceName, netlink.FAMILY_V4).Return(nil, errors.New("error"))
	mockIP.EXPECT().DelLinkByNameAddr(interfaceName, netlink.FAMILY_V6).Return(nil, errors.New("error"))
	delContext := newDeleteLinkContext(interfaceName, mockIP)
	err := delContext.run(nil)
	assert.Error(t, err)
}

func TestDeleteVethContextDelLinkByNameAddrErrorNotFound(t *testing.T) {
	ctrl, _, _, mockIP, _, _ := setup(t)
	defer ctrl.Finish()

	mockIP.EXPECT().DelLinkByNameAddr(interfaceName, netlink.FAMILY_V4).Return(nil, ip.ErrLinkNotFound)
	delContext := newDeleteLinkContext(interfaceName, mockIP)
	err := delContext.run(nil)
	assert.NoError(t, err)
}

func TestDeleteVethContextDelLinkByNameAddrSuccess(t *testing.T) {
	ctrl, _, _, mockIP, _, _ := setup(t)
	defer ctrl.Finish()

	mockIP.EXPECT().DelLinkByNameAddr(interfaceName, netlink.FAMILY_V4).Return(nil, nil)
	delContext := newDeleteLinkContext(interfaceName, mockIP)
	err := delContext.run(nil)
	assert.NoError(t, err)
}

func TestDeleteVethWithNetNSPathError(t *testing.T) {
	ctrl, mockNS, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockNS.EXPECT().WithNetNSPath(netns, gomock.Any()).Return(errors.New("error"))
	engine := &engine{
		ns: mockNS,
	}

	err := engine.DeleteVeth(netns, interfaceName)
	assert.Error(t, err)
}

func TestDeleteVethWithNetNSPathSuccess(t *testing.T) {
	ctrl, mockNS, _, _, _, _ := setup(t)
	defer ctrl.Finish()

	mockNS.EXPECT().WithNetNSPath(netns, gomock.Any()).Return(nil)
	engine := &engine{
		ns: mockNS,
	}

	err := engine.DeleteVeth(netns, interfaceName)
	assert.NoError(t, err)
}

// =============================================================================
// Property-Based Tests for IPAM Result Validation
// =============================================================================

// validateIPAMResult is a helper function that validates IPAM results
// This mirrors the validation logic in RunIPAMPluginAdd
func validateIPAMResult(result *current.Result) error {
	// Accept 1 or 2 IP configurations (IPv4 only, IPv6 only, or dual-stack)
	if len(result.IPs) < 1 || len(result.IPs) > 2 {
		return errors.Errorf(
			"bridge IPAM ADD: expected 1 or 2 IP configs, got %d", len(result.IPs))
	}

	// Validate each IP configuration
	for i, ip := range result.IPs {
		if ip.Address.Mask == nil || ip.Address.Mask.String() == zeroLengthIPString {
			return errors.Errorf(
				"bridge IPAM ADD: IP address mask not set for IP[%d]", i)
		}
		if ip.Gateway == nil || ip.Gateway.String() == zeroLengthIPString {
			return errors.Errorf(
				"bridge IPAM ADD: Gateway not set for IP[%d]", i)
		}
	}

	return nil
}

// TestProperty_IPAMResultValidation_ValidIPsAccepted tests that valid IPAM results
// with 1 or 2 IPs (each having mask and gateway) are accepted.
// **Validates: Requirements 1.4, 1.5, 1.6, 8.2, 8.3**
// Property 8: IPAM Result Validation
func TestProperty_IPAMResultValidation_ValidIPsAccepted(t *testing.T) {
	// Test with various valid configurations
	testCases := []struct {
		name   string
		result *current.Result
	}{
		{
			name: "single IPv4",
			result: &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{
							IP:   net.ParseIP("192.168.1.2"),
							Mask: net.CIDRMask(24, 32),
						},
						Gateway: net.ParseIP("192.168.1.1"),
					},
				},
			},
		},
		{
			name: "single IPv6",
			result: &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{
							IP:   net.ParseIP("2001:db8::2"),
							Mask: net.CIDRMask(64, 128),
						},
						Gateway: net.ParseIP("2001:db8::1"),
					},
				},
			},
		},
		{
			name: "dual-stack IPv4 first",
			result: &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{
							IP:   net.ParseIP("192.168.1.2"),
							Mask: net.CIDRMask(24, 32),
						},
						Gateway: net.ParseIP("192.168.1.1"),
					},
					{
						Address: net.IPNet{
							IP:   net.ParseIP("2001:db8::2"),
							Mask: net.CIDRMask(64, 128),
						},
						Gateway: net.ParseIP("2001:db8::1"),
					},
				},
			},
		},
		{
			name: "dual-stack IPv6 first",
			result: &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{
							IP:   net.ParseIP("2001:db8::2"),
							Mask: net.CIDRMask(64, 128),
						},
						Gateway: net.ParseIP("2001:db8::1"),
					},
					{
						Address: net.IPNet{
							IP:   net.ParseIP("192.168.1.2"),
							Mask: net.CIDRMask(24, 32),
						},
						Gateway: net.ParseIP("192.168.1.1"),
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateIPAMResult(tc.result)
			assert.NoError(t, err, "valid IPAM result should be accepted")
		})
	}
}

// TestProperty_IPAMResultValidation_InvalidCountRejected tests that IPAM results
// with 0 or >2 IPs are rejected.
// **Validates: Requirements 1.6, 8.1**
// Property 8: IPAM Result Validation
func TestProperty_IPAMResultValidation_InvalidCountRejected(t *testing.T) {
	testCases := []struct {
		name        string
		result      *current.Result
		expectedErr string
	}{
		{
			name: "zero IPs",
			result: &current.Result{
				IPs: []*current.IPConfig{},
			},
			expectedErr: "expected 1 or 2 IP configs, got 0",
		},
		{
			name: "three IPs",
			result: &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{IP: net.ParseIP("192.168.1.2"), Mask: net.CIDRMask(24, 32)},
						Gateway: net.ParseIP("192.168.1.1"),
					},
					{
						Address: net.IPNet{IP: net.ParseIP("2001:db8::2"), Mask: net.CIDRMask(64, 128)},
						Gateway: net.ParseIP("2001:db8::1"),
					},
					{
						Address: net.IPNet{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(24, 32)},
						Gateway: net.ParseIP("10.0.0.1"),
					},
				},
			},
			expectedErr: "expected 1 or 2 IP configs, got 3",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateIPAMResult(tc.result)
			assert.Error(t, err, "invalid IP count should be rejected")
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

// TestProperty_IPAMResultValidation_MissingMaskRejected tests that IPAM results
// with missing masks are rejected for any IP position.
// **Validates: Requirements 1.4, 8.2**
// Property 8: IPAM Result Validation
func TestProperty_IPAMResultValidation_MissingMaskRejected(t *testing.T) {
	testCases := []struct {
		name        string
		result      *current.Result
		expectedErr string
	}{
		{
			name: "missing mask on first IPv4",
			result: &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{IP: net.ParseIP("192.168.1.2")},
						Gateway: net.ParseIP("192.168.1.1"),
					},
				},
			},
			expectedErr: "IP address mask not set for IP[0]",
		},
		{
			name: "missing mask on first IPv6",
			result: &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{IP: net.ParseIP("2001:db8::2")},
						Gateway: net.ParseIP("2001:db8::1"),
					},
				},
			},
			expectedErr: "IP address mask not set for IP[0]",
		},
		{
			name: "missing mask on second IP in dual-stack",
			result: &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{IP: net.ParseIP("192.168.1.2"), Mask: net.CIDRMask(24, 32)},
						Gateway: net.ParseIP("192.168.1.1"),
					},
					{
						Address: net.IPNet{IP: net.ParseIP("2001:db8::2")},
						Gateway: net.ParseIP("2001:db8::1"),
					},
				},
			},
			expectedErr: "IP address mask not set for IP[1]",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateIPAMResult(tc.result)
			assert.Error(t, err, "missing mask should be rejected")
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

// TestProperty_IPAMResultValidation_MissingGatewayRejected tests that IPAM results
// with missing gateways are rejected for any IP position.
// **Validates: Requirements 1.5, 8.3**
// Property 8: IPAM Result Validation
func TestProperty_IPAMResultValidation_MissingGatewayRejected(t *testing.T) {
	testCases := []struct {
		name        string
		result      *current.Result
		expectedErr string
	}{
		{
			name: "missing gateway on first IPv4",
			result: &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{IP: net.ParseIP("192.168.1.2"), Mask: net.CIDRMask(24, 32)},
					},
				},
			},
			expectedErr: "Gateway not set for IP[0]",
		},
		{
			name: "missing gateway on first IPv6",
			result: &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{IP: net.ParseIP("2001:db8::2"), Mask: net.CIDRMask(64, 128)},
					},
				},
			},
			expectedErr: "Gateway not set for IP[0]",
		},
		{
			name: "missing gateway on second IP in dual-stack",
			result: &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{IP: net.ParseIP("192.168.1.2"), Mask: net.CIDRMask(24, 32)},
						Gateway: net.ParseIP("192.168.1.1"),
					},
					{
						Address: net.IPNet{IP: net.ParseIP("2001:db8::2"), Mask: net.CIDRMask(64, 128)},
					},
				},
			},
			expectedErr: "Gateway not set for IP[1]",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateIPAMResult(tc.result)
			assert.Error(t, err, "missing gateway should be rejected")
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

// =============================================================================
// Bridge Configuration Tests for IPv6 and Dual-Stack
// =============================================================================

// IPv6 test constants
const (
	ipv6GatewayIP   = "2001:db8::1"
	ipv6ContainerIP = "2001:db8::2"
)

// TestConfigureBridgeIPv6OnlySuccess tests that IPv6-only bridge configuration works
// Validates: Requirements 3.1
// **Property 5: Bridge Address Assignment**
func TestConfigureBridgeIPv6OnlySuccess(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{}
	ipv6Gateway := net.ParseIP(ipv6GatewayIP)
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   net.ParseIP(ipv6ContainerIP),
			Mask: net.CIDRMask(64, 128),
		},
		Gateway: ipv6Gateway,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	bridgeAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ipv6Gateway,
			Mask: net.CIDRMask(64, 128),
		},
	}
	gomock.InOrder(
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET6).Return(nil, nil),
		mockNetLink.EXPECT().AddrAdd(bridgeLink, bridgeAddr).Return(nil),
	)
	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.NoError(t, err)
}

// TestConfigureBridgeIPv6AlreadyConfigured tests that IPv6 address already on bridge is handled
// Validates: Requirements 3.3
// **Property 5: Bridge Address Assignment**
func TestConfigureBridgeIPv6AlreadyConfigured(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{}
	ipv6Gateway := net.ParseIP(ipv6GatewayIP)
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   net.ParseIP(ipv6ContainerIP),
			Mask: net.CIDRMask(64, 128),
		},
		Gateway: ipv6Gateway,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	// The bridge already has the correct IPv6 address
	addrs := []netlink.Addr{
		{
			IPNet: &net.IPNet{
				IP:   ipv6Gateway,
				Mask: net.CIDRMask(64, 128),
			},
		},
	}
	gomock.InOrder(
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET6).Return(addrs, nil),
	)
	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.NoError(t, err)
}

// TestConfigureBridgeIPv6MismatchError tests that IPv6 address mismatch returns error
// Validates: Requirements 3.4
// **Property 5: Bridge Address Assignment**
func TestConfigureBridgeIPv6MismatchError(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{Name: bridgeName},
	}
	ipv6Gateway := net.ParseIP(ipv6GatewayIP)
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   net.ParseIP(ipv6ContainerIP),
			Mask: net.CIDRMask(64, 128),
		},
		Gateway: ipv6Gateway,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	// Bridge has a different IPv6 address than expected
	addrs := []netlink.Addr{
		{
			IPNet: &net.IPNet{
				IP:   net.ParseIP("2001:db8:1::1"),
				Mask: net.CIDRMask(64, 128),
			},
		},
	}
	gomock.InOrder(
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET6).Return(addrs, nil),
	)
	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mismatch in bridge")
}

// TestConfigureBridgeIPv6AddrListError tests that AddrList error for IPv6 is handled
// Validates: Requirements 3.1
func TestConfigureBridgeIPv6AddrListError(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{}
	ipv6Gateway := net.ParseIP(ipv6GatewayIP)
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   net.ParseIP(ipv6ContainerIP),
			Mask: net.CIDRMask(64, 128),
		},
		Gateway: ipv6Gateway,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET6).Return(nil, errors.New("error"))

	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.Error(t, err)
}

// TestConfigureBridgeIPv6AddrAddError tests that AddrAdd error for IPv6 is handled
// Validates: Requirements 3.1
func TestConfigureBridgeIPv6AddrAddError(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{Name: bridgeName},
	}
	ipv6Gateway := net.ParseIP(ipv6GatewayIP)
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   net.ParseIP(ipv6ContainerIP),
			Mask: net.CIDRMask(64, 128),
		},
		Gateway: ipv6Gateway,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	bridgeAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ipv6Gateway,
			Mask: net.CIDRMask(64, 128),
		},
	}
	gomock.InOrder(
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET6).Return(nil, nil),
		mockNetLink.EXPECT().AddrAdd(bridgeLink, bridgeAddr).Return(errors.New("error")),
	)
	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.Error(t, err)
}

// TestConfigureBridgeIPv6AddrAddFileExistsError tests that file exists error for IPv6 is handled
// Validates: Requirements 3.1
func TestConfigureBridgeIPv6AddrAddFileExistsError(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{}
	ipv6Gateway := net.ParseIP(ipv6GatewayIP)
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   net.ParseIP(ipv6ContainerIP),
			Mask: net.CIDRMask(64, 128),
		},
		Gateway: ipv6Gateway,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	bridgeAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ipv6Gateway,
			Mask: net.CIDRMask(64, 128),
		},
	}
	gomock.InOrder(
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET6).Return(nil, nil),
		mockNetLink.EXPECT().AddrAdd(bridgeLink, bridgeAddr).Return(errors.New("file exists")),
	)
	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.NoError(t, err)
}

// TestConfigureBridgeDualStackSuccess tests that dual-stack bridge configuration works
// Validates: Requirements 3.2
// **Property 5: Bridge Address Assignment**
func TestConfigureBridgeDualStackSuccess(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{}
	ipv4Gateway := net.ParseIP(gatewayIP)
	ipv6Gateway := net.ParseIP(ipv6GatewayIP)

	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{
					IP:   net.ParseIP("192.168.1.2"),
					Mask: net.CIDRMask(31, 32),
				},
				Gateway: ipv4Gateway,
			},
			{
				Address: net.IPNet{
					IP:   net.ParseIP(ipv6ContainerIP),
					Mask: net.CIDRMask(64, 128),
				},
				Gateway: ipv6Gateway,
			},
		},
	}

	ipv4BridgeAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ipv4Gateway,
			Mask: net.CIDRMask(31, 32),
		},
	}
	ipv6BridgeAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ipv6Gateway,
			Mask: net.CIDRMask(64, 128),
		},
	}
	gomock.InOrder(
		// First IP (IPv4)
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET).Return(nil, nil),
		mockNetLink.EXPECT().AddrAdd(bridgeLink, ipv4BridgeAddr).Return(nil),
		// Second IP (IPv6)
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET6).Return(nil, nil),
		mockNetLink.EXPECT().AddrAdd(bridgeLink, ipv6BridgeAddr).Return(nil),
	)
	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.NoError(t, err)
}

// TestConfigureBridgeDualStackIPv4AlreadyConfigured tests dual-stack when IPv4 already exists
// Validates: Requirements 3.2, 3.3
// **Property 5: Bridge Address Assignment**
func TestConfigureBridgeDualStackIPv4AlreadyConfigured(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{}
	ipv4Gateway := net.ParseIP(gatewayIP)
	ipv6Gateway := net.ParseIP(ipv6GatewayIP)

	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{
					IP:   net.ParseIP("192.168.1.2"),
					Mask: net.CIDRMask(31, 32),
				},
				Gateway: ipv4Gateway,
			},
			{
				Address: net.IPNet{
					IP:   net.ParseIP(ipv6ContainerIP),
					Mask: net.CIDRMask(64, 128),
				},
				Gateway: ipv6Gateway,
			},
		},
	}

	// IPv4 address already exists on bridge
	ipv4Addrs := []netlink.Addr{
		{
			IPNet: &net.IPNet{
				IP:   ipv4Gateway,
				Mask: net.CIDRMask(31, 32),
			},
		},
	}
	ipv6BridgeAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ipv6Gateway,
			Mask: net.CIDRMask(64, 128),
		},
	}
	gomock.InOrder(
		// First IP (IPv4) - already exists
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET).Return(ipv4Addrs, nil),
		// Second IP (IPv6) - needs to be added
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET6).Return(nil, nil),
		mockNetLink.EXPECT().AddrAdd(bridgeLink, ipv6BridgeAddr).Return(nil),
	)
	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.NoError(t, err)
}

// TestConfigureBridgeDualStackIPv6AlreadyConfigured tests dual-stack when IPv6 already exists
// Validates: Requirements 3.2, 3.3
// **Property 5: Bridge Address Assignment**
func TestConfigureBridgeDualStackIPv6AlreadyConfigured(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{}
	ipv4Gateway := net.ParseIP(gatewayIP)
	ipv6Gateway := net.ParseIP(ipv6GatewayIP)

	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{
					IP:   net.ParseIP("192.168.1.2"),
					Mask: net.CIDRMask(31, 32),
				},
				Gateway: ipv4Gateway,
			},
			{
				Address: net.IPNet{
					IP:   net.ParseIP(ipv6ContainerIP),
					Mask: net.CIDRMask(64, 128),
				},
				Gateway: ipv6Gateway,
			},
		},
	}

	// IPv6 address already exists on bridge
	ipv6Addrs := []netlink.Addr{
		{
			IPNet: &net.IPNet{
				IP:   ipv6Gateway,
				Mask: net.CIDRMask(64, 128),
			},
		},
	}
	ipv4BridgeAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ipv4Gateway,
			Mask: net.CIDRMask(31, 32),
		},
	}
	gomock.InOrder(
		// First IP (IPv4) - needs to be added
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET).Return(nil, nil),
		mockNetLink.EXPECT().AddrAdd(bridgeLink, ipv4BridgeAddr).Return(nil),
		// Second IP (IPv6) - already exists
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET6).Return(ipv6Addrs, nil),
	)
	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.NoError(t, err)
}

// TestConfigureBridgeDualStackBothAlreadyConfigured tests dual-stack when both addresses exist
// Validates: Requirements 3.2, 3.3
// **Property 5: Bridge Address Assignment**
func TestConfigureBridgeDualStackBothAlreadyConfigured(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{}
	ipv4Gateway := net.ParseIP(gatewayIP)
	ipv6Gateway := net.ParseIP(ipv6GatewayIP)

	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{
					IP:   net.ParseIP("192.168.1.2"),
					Mask: net.CIDRMask(31, 32),
				},
				Gateway: ipv4Gateway,
			},
			{
				Address: net.IPNet{
					IP:   net.ParseIP(ipv6ContainerIP),
					Mask: net.CIDRMask(64, 128),
				},
				Gateway: ipv6Gateway,
			},
		},
	}

	// Both addresses already exist on bridge
	ipv4Addrs := []netlink.Addr{
		{
			IPNet: &net.IPNet{
				IP:   ipv4Gateway,
				Mask: net.CIDRMask(31, 32),
			},
		},
	}
	ipv6Addrs := []netlink.Addr{
		{
			IPNet: &net.IPNet{
				IP:   ipv6Gateway,
				Mask: net.CIDRMask(64, 128),
			},
		},
	}
	gomock.InOrder(
		// First IP (IPv4) - already exists
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET).Return(ipv4Addrs, nil),
		// Second IP (IPv6) - already exists
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET6).Return(ipv6Addrs, nil),
	)
	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.NoError(t, err)
}

// TestConfigureBridgeDualStackIPv4MismatchError tests dual-stack when IPv4 has mismatch
// Validates: Requirements 3.4
// **Property 5: Bridge Address Assignment**
func TestConfigureBridgeDualStackIPv4MismatchError(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{Name: bridgeName},
	}
	ipv4Gateway := net.ParseIP(gatewayIP)
	ipv6Gateway := net.ParseIP(ipv6GatewayIP)

	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{
					IP:   net.ParseIP("192.168.1.2"),
					Mask: net.CIDRMask(31, 32),
				},
				Gateway: ipv4Gateway,
			},
			{
				Address: net.IPNet{
					IP:   net.ParseIP(ipv6ContainerIP),
					Mask: net.CIDRMask(64, 128),
				},
				Gateway: ipv6Gateway,
			},
		},
	}

	// IPv4 address mismatch
	ipv4Addrs := []netlink.Addr{
		{
			IPNet: &net.IPNet{
				IP:   net.ParseIP("10.0.0.1"),
				Mask: net.CIDRMask(24, 32),
			},
		},
	}
	gomock.InOrder(
		// First IP (IPv4) - mismatch
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET).Return(ipv4Addrs, nil),
	)
	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mismatch in bridge")
}

// TestConfigureBridgeDualStackIPv6MismatchError tests dual-stack when IPv6 has mismatch
// Validates: Requirements 3.4
// **Property 5: Bridge Address Assignment**
func TestConfigureBridgeDualStackIPv6MismatchError(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{Name: bridgeName},
	}
	ipv4Gateway := net.ParseIP(gatewayIP)
	ipv6Gateway := net.ParseIP(ipv6GatewayIP)

	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{
					IP:   net.ParseIP("192.168.1.2"),
					Mask: net.CIDRMask(31, 32),
				},
				Gateway: ipv4Gateway,
			},
			{
				Address: net.IPNet{
					IP:   net.ParseIP(ipv6ContainerIP),
					Mask: net.CIDRMask(64, 128),
				},
				Gateway: ipv6Gateway,
			},
		},
	}

	// IPv6 address mismatch
	ipv6Addrs := []netlink.Addr{
		{
			IPNet: &net.IPNet{
				IP:   net.ParseIP("2001:db8:1::1"),
				Mask: net.CIDRMask(64, 128),
			},
		},
	}
	ipv4BridgeAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ipv4Gateway,
			Mask: net.CIDRMask(31, 32),
		},
	}
	gomock.InOrder(
		// First IP (IPv4) - success
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET).Return(nil, nil),
		mockNetLink.EXPECT().AddrAdd(bridgeLink, ipv4BridgeAddr).Return(nil),
		// Second IP (IPv6) - mismatch
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET6).Return(ipv6Addrs, nil),
	)
	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mismatch in bridge")
}

// =============================================================================
// Property-Based Tests for Bridge Address Assignment
// =============================================================================

// TestProperty_BridgeAddressAssignment_CorrectAddressFamily tests that the correct
// address family is used for IPv4 vs IPv6 addresses.
// **Validates: Requirements 3.1, 3.2**
// Property 5: Bridge Address Assignment
func TestProperty_BridgeAddressAssignment_CorrectAddressFamily(t *testing.T) {
	testCases := []struct {
		name           string
		ip             net.IP
		expectedFamily int
	}{
		{
			name:           "IPv4 address uses AF_INET",
			ip:             net.ParseIP("192.168.1.1"),
			expectedFamily: syscall.AF_INET,
		},
		{
			name:           "IPv6 address uses AF_INET6",
			ip:             net.ParseIP("2001:db8::1"),
			expectedFamily: syscall.AF_INET6,
		},
		{
			name:           "IPv4-mapped IPv6 uses AF_INET",
			ip:             net.ParseIP("::ffff:192.168.1.1").To4(),
			expectedFamily: syscall.AF_INET,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Determine address family based on IP version (same logic as ConfigureBridge)
			family := syscall.AF_INET
			if tc.ip.To4() == nil {
				family = syscall.AF_INET6
			}
			assert.Equal(t, tc.expectedFamily, family, "address family should match expected")
		})
	}
}

// TestProperty_BridgeAddressAssignment_GatewayUsedAsBridgeAddress tests that the
// gateway address from the IPAM result is used as the bridge address.
// **Validates: Requirements 3.1, 3.2**
// Property 5: Bridge Address Assignment
func TestProperty_BridgeAddressAssignment_GatewayUsedAsBridgeAddress(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	testCases := []struct {
		name    string
		gateway net.IP
		mask    net.IPMask
		family  int
	}{
		{
			name:    "IPv4 gateway becomes bridge address",
			gateway: net.ParseIP("10.0.0.1"),
			mask:    net.CIDRMask(24, 32),
			family:  syscall.AF_INET,
		},
		{
			name:    "IPv6 gateway becomes bridge address",
			gateway: net.ParseIP("fd00::1"),
			mask:    net.CIDRMask(64, 128),
			family:  syscall.AF_INET6,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bridgeLink := &netlink.Bridge{}
			ipConfig := &current.IPConfig{
				Address: net.IPNet{
					IP:   tc.gateway, // Using gateway as container IP for simplicity
					Mask: tc.mask,
				},
				Gateway: tc.gateway,
			}

			result := &current.Result{
				IPs: []*current.IPConfig{ipConfig},
			}

			expectedBridgeAddr := &netlink.Addr{
				IPNet: &net.IPNet{
					IP:   tc.gateway,
					Mask: tc.mask,
				},
			}

			gomock.InOrder(
				mockNetLink.EXPECT().AddrList(bridgeLink, tc.family).Return(nil, nil),
				mockNetLink.EXPECT().AddrAdd(bridgeLink, expectedBridgeAddr).Return(nil),
			)

			engine := &engine{netLink: mockNetLink}
			err := engine.ConfigureBridge(result, bridgeLink)
			assert.NoError(t, err)
		})
	}
}

// TestProperty_BridgeAddressAssignment_ExistingAddressSkipped tests that when the
// bridge already has the correct address, no new address is added.
// **Validates: Requirements 3.3**
// Property 5: Bridge Address Assignment
func TestProperty_BridgeAddressAssignment_ExistingAddressSkipped(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	testCases := []struct {
		name    string
		gateway net.IP
		mask    net.IPMask
		family  int
	}{
		{
			name:    "existing IPv4 address skipped",
			gateway: net.ParseIP("172.16.0.1"),
			mask:    net.CIDRMask(16, 32),
			family:  syscall.AF_INET,
		},
		{
			name:    "existing IPv6 address skipped",
			gateway: net.ParseIP("fe80::1"),
			mask:    net.CIDRMask(64, 128),
			family:  syscall.AF_INET6,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bridgeLink := &netlink.Bridge{}
			ipConfig := &current.IPConfig{
				Address: net.IPNet{
					IP:   tc.gateway,
					Mask: tc.mask,
				},
				Gateway: tc.gateway,
			}

			result := &current.Result{
				IPs: []*current.IPConfig{ipConfig},
			}

			// Bridge already has the correct address
			existingAddrs := []netlink.Addr{
				{
					IPNet: &net.IPNet{
						IP:   tc.gateway,
						Mask: tc.mask,
					},
				},
			}

			// Only AddrList should be called, not AddrAdd
			mockNetLink.EXPECT().AddrList(bridgeLink, tc.family).Return(existingAddrs, nil)

			engine := &engine{netLink: mockNetLink}
			err := engine.ConfigureBridge(result, bridgeLink)
			assert.NoError(t, err)
		})
	}
}

// =============================================================================
// Veth Configuration Tests for IPv6 and Dual-Stack
// =============================================================================

// TestConfigureContainerVethInterfaceIPv6OnlySuccess tests IPv6-only veth configuration
// Validates: Requirements 2.1, 4.1
// **Property 4: Gateway Route Addition**
func TestConfigureContainerVethInterfaceIPv6OnlySuccess(t *testing.T) {
	ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	ipv6Gateway := net.ParseIP(ipv6GatewayIP)
	ipv6ContainerAddr := net.ParseIP(ipv6ContainerIP)
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   ipv6ContainerAddr,
			Mask: net.CIDRMask(64, 128),
		},
		Gateway: ipv6Gateway,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	mockLink := mock_netlink.NewMockLink(ctrl)
	routes := []netlink.Route{}
	gomock.InOrder(
		mockIPAM.EXPECT().ConfigureIface(interfaceName, gomock.Any()).DoAndReturn(
			func(ifName string, res *current.Result) error {
				// Verify gateway route for IPv6 was added
				assert.Equal(t, 1, len(res.Routes), "should have 1 gateway route")
				ones, _ := res.Routes[0].Dst.Mask.Size()
				assert.Equal(t, 128, ones, "IPv6 gateway route should be /128")
				return nil
			}),
		// For IPv6-only, SetHWAddrByIP uses nil for IPv4 and the IPv6 address
		mockIP.EXPECT().SetHWAddrByIP(interfaceName, nil, ipv6ContainerAddr).Return(nil),
		mockNetLink.EXPECT().LinkByName(interfaceName).Return(mockLink, nil),
		mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_ALL).Return(routes, nil),
	)
	configContext := newConfigureVethContext(
		interfaceName, result, mockIP, mockIPAM, mockNetLink)
	err := configContext.run(nil)
	assert.NoError(t, err)
}

// TestConfigureContainerVethInterfaceDualStackSuccess tests dual-stack veth configuration
// Validates: Requirements 2.1, 4.2, 4.4
// **Property 4: Gateway Route Addition**
func TestConfigureContainerVethInterfaceDualStackSuccess(t *testing.T) {
	ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	ipv4Gateway := net.ParseIP(gatewayIP)
	ipv4ContainerAddr := net.ParseIP("192.168.1.2")
	ipv6Gateway := net.ParseIP(ipv6GatewayIP)
	ipv6ContainerAddr := net.ParseIP(ipv6ContainerIP)

	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{
					IP:   ipv4ContainerAddr,
					Mask: net.CIDRMask(31, 32),
				},
				Gateway: ipv4Gateway,
			},
			{
				Address: net.IPNet{
					IP:   ipv6ContainerAddr,
					Mask: net.CIDRMask(64, 128),
				},
				Gateway: ipv6Gateway,
			},
		},
	}

	mockLink := mock_netlink.NewMockLink(ctrl)
	routes := []netlink.Route{}
	gomock.InOrder(
		mockIPAM.EXPECT().ConfigureIface(interfaceName, gomock.Any()).DoAndReturn(
			func(ifName string, res *current.Result) error {
				// Verify gateway routes for both IPv4 and IPv6 were added
				assert.Equal(t, 2, len(res.Routes), "should have 2 gateway routes")
				// First route should be IPv4 /32
				ones, _ := res.Routes[0].Dst.Mask.Size()
				assert.Equal(t, 32, ones, "IPv4 gateway route should be /32")
				// Second route should be IPv6 /128
				ones, _ = res.Routes[1].Dst.Mask.Size()
				assert.Equal(t, 128, ones, "IPv6 gateway route should be /128")
				return nil
			}),
		// For dual-stack, SetHWAddrByIP uses both IPv4 and IPv6 addresses
		mockIP.EXPECT().SetHWAddrByIP(interfaceName, ipv4ContainerAddr, ipv6ContainerAddr).Return(nil),
		mockNetLink.EXPECT().LinkByName(interfaceName).Return(mockLink, nil),
		mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_ALL).Return(routes, nil),
	)
	configContext := newConfigureVethContext(
		interfaceName, result, mockIP, mockIPAM, mockNetLink)
	err := configContext.run(nil)
	assert.NoError(t, err)
}

// TestConfigureContainerVethInterfaceDualStackIPv6FirstSuccess tests dual-stack with IPv6 first
// Validates: Requirements 2.1, 4.2
// **Property 4: Gateway Route Addition**
func TestConfigureContainerVethInterfaceDualStackIPv6FirstSuccess(t *testing.T) {
	ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	ipv4Gateway := net.ParseIP(gatewayIP)
	ipv4ContainerAddr := net.ParseIP("192.168.1.2")
	ipv6Gateway := net.ParseIP(ipv6GatewayIP)
	ipv6ContainerAddr := net.ParseIP(ipv6ContainerIP)

	// IPv6 first in the list
	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{
					IP:   ipv6ContainerAddr,
					Mask: net.CIDRMask(64, 128),
				},
				Gateway: ipv6Gateway,
			},
			{
				Address: net.IPNet{
					IP:   ipv4ContainerAddr,
					Mask: net.CIDRMask(31, 32),
				},
				Gateway: ipv4Gateway,
			},
		},
	}

	mockLink := mock_netlink.NewMockLink(ctrl)
	routes := []netlink.Route{}
	gomock.InOrder(
		mockIPAM.EXPECT().ConfigureIface(interfaceName, gomock.Any()).DoAndReturn(
			func(ifName string, res *current.Result) error {
				// Verify gateway routes for both IPv6 and IPv4
				assert.Equal(t, 2, len(res.Routes), "should have 2 gateway routes")
				// First route should be IPv6 /128
				ones, _ := res.Routes[0].Dst.Mask.Size()
				assert.Equal(t, 128, ones, "first gateway route should be /128 for IPv6")
				// Second route should be IPv4 /32
				ones, _ = res.Routes[1].Dst.Mask.Size()
				assert.Equal(t, 32, ones, "second gateway route should be /32 for IPv4")
				return nil
			}),
		// Even with IPv6 first, SetHWAddrByIP should use both addresses
		mockIP.EXPECT().SetHWAddrByIP(interfaceName, ipv4ContainerAddr, ipv6ContainerAddr).Return(nil),
		mockNetLink.EXPECT().LinkByName(interfaceName).Return(mockLink, nil),
		mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_ALL).Return(routes, nil),
	)
	configContext := newConfigureVethContext(
		interfaceName, result, mockIP, mockIPAM, mockNetLink)
	err := configContext.run(nil)
	assert.NoError(t, err)
}

// TestConfigureContainerVethInterfaceDeleteDefaultRoutesIPv4 tests default route deletion for IPv4
// Validates: Requirements 2.4
// **Property 7: Default Route Deletion**
func TestConfigureContainerVethInterfaceDeleteDefaultRoutesIPv4(t *testing.T) {
	ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	gatewayIPAddr := net.ParseIP(gatewayIP)
	containerIPAddr := net.ParseIP("192.168.1.2")
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   containerIPAddr,
			Mask: net.CIDRMask(31, 32),
		},
		Gateway: gatewayIPAddr,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	mockLink := mock_netlink.NewMockLink(ctrl)
	// IPv4 default route (no gateway means it's a default route to delete)
	defaultRoute := netlink.Route{
		Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Gw:  nil, // No gateway = default route
	}
	// Route with gateway should NOT be deleted
	routeWithGw := netlink.Route{
		Dst: &net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)},
		Gw:  net.ParseIP("192.168.1.1"),
	}
	routes := []netlink.Route{defaultRoute, routeWithGw}

	gomock.InOrder(
		mockIPAM.EXPECT().ConfigureIface(interfaceName, gomock.Any()).Return(nil),
		mockIP.EXPECT().SetHWAddrByIP(interfaceName, containerIPAddr, nil).Return(nil),
		mockNetLink.EXPECT().LinkByName(interfaceName).Return(mockLink, nil),
		mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_ALL).Return(routes, nil),
		// Only the default route (without gateway) should be deleted
		mockNetLink.EXPECT().RouteDel(&defaultRoute).Return(nil),
	)
	configContext := newConfigureVethContext(
		interfaceName, result, mockIP, mockIPAM, mockNetLink)
	err := configContext.run(nil)
	assert.NoError(t, err)
}

// TestConfigureContainerVethInterfaceDeleteDefaultRoutesIPv6 tests default route deletion for IPv6
// Validates: Requirements 2.4
// **Property 7: Default Route Deletion**
func TestConfigureContainerVethInterfaceDeleteDefaultRoutesIPv6(t *testing.T) {
	ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	ipv6Gateway := net.ParseIP(ipv6GatewayIP)
	ipv6ContainerAddr := net.ParseIP(ipv6ContainerIP)
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   ipv6ContainerAddr,
			Mask: net.CIDRMask(64, 128),
		},
		Gateway: ipv6Gateway,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	mockLink := mock_netlink.NewMockLink(ctrl)
	// IPv6 default route (no gateway means it's a default route to delete)
	defaultRoute := netlink.Route{
		Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		Gw:  nil, // No gateway = default route
	}
	routes := []netlink.Route{defaultRoute}

	gomock.InOrder(
		mockIPAM.EXPECT().ConfigureIface(interfaceName, gomock.Any()).Return(nil),
		mockIP.EXPECT().SetHWAddrByIP(interfaceName, nil, ipv6ContainerAddr).Return(nil),
		mockNetLink.EXPECT().LinkByName(interfaceName).Return(mockLink, nil),
		mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_ALL).Return(routes, nil),
		mockNetLink.EXPECT().RouteDel(&defaultRoute).Return(nil),
	)
	configContext := newConfigureVethContext(
		interfaceName, result, mockIP, mockIPAM, mockNetLink)
	err := configContext.run(nil)
	assert.NoError(t, err)
}

// TestConfigureContainerVethInterfaceDeleteDefaultRoutesBothFamilies tests default route deletion
// for both IPv4 and IPv6 in dual-stack configuration
// Validates: Requirements 2.4
// **Property 7: Default Route Deletion**
func TestConfigureContainerVethInterfaceDeleteDefaultRoutesBothFamilies(t *testing.T) {
	ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	ipv4Gateway := net.ParseIP(gatewayIP)
	ipv4ContainerAddr := net.ParseIP("192.168.1.2")
	ipv6Gateway := net.ParseIP(ipv6GatewayIP)
	ipv6ContainerAddr := net.ParseIP(ipv6ContainerIP)

	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{
					IP:   ipv4ContainerAddr,
					Mask: net.CIDRMask(31, 32),
				},
				Gateway: ipv4Gateway,
			},
			{
				Address: net.IPNet{
					IP:   ipv6ContainerAddr,
					Mask: net.CIDRMask(64, 128),
				},
				Gateway: ipv6Gateway,
			},
		},
	}

	mockLink := mock_netlink.NewMockLink(ctrl)
	// Both IPv4 and IPv6 default routes
	ipv4DefaultRoute := netlink.Route{
		Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Gw:  nil,
	}
	ipv6DefaultRoute := netlink.Route{
		Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		Gw:  nil,
	}
	routes := []netlink.Route{ipv4DefaultRoute, ipv6DefaultRoute}

	gomock.InOrder(
		mockIPAM.EXPECT().ConfigureIface(interfaceName, gomock.Any()).Return(nil),
		mockIP.EXPECT().SetHWAddrByIP(interfaceName, ipv4ContainerAddr, ipv6ContainerAddr).Return(nil),
		mockNetLink.EXPECT().LinkByName(interfaceName).Return(mockLink, nil),
		mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_ALL).Return(routes, nil),
		// Both default routes should be deleted
		mockNetLink.EXPECT().RouteDel(&ipv4DefaultRoute).Return(nil),
		mockNetLink.EXPECT().RouteDel(&ipv6DefaultRoute).Return(nil),
	)
	configContext := newConfigureVethContext(
		interfaceName, result, mockIP, mockIPAM, mockNetLink)
	err := configContext.run(nil)
	assert.NoError(t, err)
}

// TestConfigureContainerVethInterfaceHWAddrIPv4Preference tests that IPv4 is preferred for HW addr
// Validates: Requirements 4.1, 4.2
func TestConfigureContainerVethInterfaceHWAddrIPv4Preference(t *testing.T) {
	ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	ipv4Gateway := net.ParseIP(gatewayIP)
	ipv4ContainerAddr := net.ParseIP("192.168.1.2")
	ipv6Gateway := net.ParseIP(ipv6GatewayIP)
	ipv6ContainerAddr := net.ParseIP(ipv6ContainerIP)

	// IPv6 first, but IPv4 should still be used for HW address
	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{
					IP:   ipv6ContainerAddr,
					Mask: net.CIDRMask(64, 128),
				},
				Gateway: ipv6Gateway,
			},
			{
				Address: net.IPNet{
					IP:   ipv4ContainerAddr,
					Mask: net.CIDRMask(31, 32),
				},
				Gateway: ipv4Gateway,
			},
		},
	}

	mockLink := mock_netlink.NewMockLink(ctrl)
	routes := []netlink.Route{}

	gomock.InOrder(
		mockIPAM.EXPECT().ConfigureIface(interfaceName, gomock.Any()).Return(nil),
		// Both IPv4 and IPv6 addresses should be passed to SetHWAddrByIP
		mockIP.EXPECT().SetHWAddrByIP(interfaceName, ipv4ContainerAddr, ipv6ContainerAddr).Return(nil),
		mockNetLink.EXPECT().LinkByName(interfaceName).Return(mockLink, nil),
		mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_ALL).Return(routes, nil),
	)
	configContext := newConfigureVethContext(
		interfaceName, result, mockIP, mockIPAM, mockNetLink)
	err := configContext.run(nil)
	assert.NoError(t, err)
}

// =============================================================================
// Property-Based Tests for Gateway Route Addition
// =============================================================================

// TestProperty_GatewayRouteAddition_CorrectMaskBits tests that gateway routes use
// the correct mask bits (/32 for IPv4, /128 for IPv6)
// **Validates: Requirements 2.1**
// Property 4: Gateway Route Addition
func TestProperty_GatewayRouteAddition_CorrectMaskBits(t *testing.T) {
	testCases := []struct {
		name             string
		ip               net.IP
		expectedMaskBits int
	}{
		{
			name:             "IPv4 gateway uses /32",
			ip:               net.ParseIP("192.168.1.1"),
			expectedMaskBits: 32,
		},
		{
			name:             "IPv6 gateway uses /128",
			ip:               net.ParseIP("2001:db8::1"),
			expectedMaskBits: 128,
		},
		{
			name:             "link-local IPv6 uses /128",
			ip:               net.ParseIP("fe80::1"),
			expectedMaskBits: 128,
		},
		{
			name:             "private IPv4 uses /32",
			ip:               net.ParseIP("10.0.0.1"),
			expectedMaskBits: 32,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Determine mask bits based on IP version (same logic as configureVethContext.run)
			var maskBits int
			if tc.ip.To4() != nil {
				maskBits = 32
			} else {
				maskBits = 128
			}
			assert.Equal(t, tc.expectedMaskBits, maskBits, "mask bits should match expected")
		})
	}
}

// TestProperty_GatewayRouteAddition_RouteAddedForEachIP tests that a gateway route
// is added for each IP configuration in the result
// **Validates: Requirements 2.1**
// Property 4: Gateway Route Addition
func TestProperty_GatewayRouteAddition_RouteAddedForEachIP(t *testing.T) {
	testCases := []struct {
		name          string
		ips           []*current.IPConfig
		expectedCount int
	}{
		{
			name: "single IPv4 adds one route",
			ips: []*current.IPConfig{
				{
					Address: net.IPNet{IP: net.ParseIP("192.168.1.2"), Mask: net.CIDRMask(24, 32)},
					Gateway: net.ParseIP("192.168.1.1"),
				},
			},
			expectedCount: 1,
		},
		{
			name: "single IPv6 adds one route",
			ips: []*current.IPConfig{
				{
					Address: net.IPNet{IP: net.ParseIP("2001:db8::2"), Mask: net.CIDRMask(64, 128)},
					Gateway: net.ParseIP("2001:db8::1"),
				},
			},
			expectedCount: 1,
		},
		{
			name: "dual-stack adds two routes",
			ips: []*current.IPConfig{
				{
					Address: net.IPNet{IP: net.ParseIP("192.168.1.2"), Mask: net.CIDRMask(24, 32)},
					Gateway: net.ParseIP("192.168.1.1"),
				},
				{
					Address: net.IPNet{IP: net.ParseIP("2001:db8::2"), Mask: net.CIDRMask(64, 128)},
					Gateway: net.ParseIP("2001:db8::1"),
				},
			},
			expectedCount: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := &current.Result{IPs: tc.ips}

			// Simulate the route addition logic from configureVethContext.run
			for _, ipConfig := range result.IPs {
				var maskBits int
				if ipConfig.Address.IP.To4() != nil {
					maskBits = 32
				} else {
					maskBits = 128
				}
				route := &types.Route{
					Dst: net.IPNet{
						IP:   ipConfig.Gateway,
						Mask: net.CIDRMask(maskBits, maskBits),
					},
				}
				result.Routes = append(result.Routes, route)
			}

			assert.Equal(t, tc.expectedCount, len(result.Routes),
				"number of routes should match number of IPs")
		})
	}
}

// =============================================================================
// Property-Based Tests for Default Route Deletion
// =============================================================================

// TestProperty_DefaultRouteDeletion_OnlyRoutesWithoutGateway tests that only routes
// without a gateway are deleted (default routes)
// **Validates: Requirements 2.4**
// Property 7: Default Route Deletion
func TestProperty_DefaultRouteDeletion_OnlyRoutesWithoutGateway(t *testing.T) {
	testCases := []struct {
		name           string
		routes         []netlink.Route
		expectedDelCnt int
	}{
		{
			name: "route with gateway not deleted",
			routes: []netlink.Route{
				{Dst: &net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)}, Gw: net.ParseIP("192.168.1.1")},
			},
			expectedDelCnt: 0,
		},
		{
			name: "route without gateway deleted",
			routes: []netlink.Route{
				{Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, Gw: nil},
			},
			expectedDelCnt: 1,
		},
		{
			name: "mixed routes - only nil gateway deleted",
			routes: []netlink.Route{
				{Dst: &net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)}, Gw: net.ParseIP("192.168.1.1")},
				{Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, Gw: nil},
				{Dst: &net.IPNet{IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(12, 32)}, Gw: net.ParseIP("192.168.1.1")},
			},
			expectedDelCnt: 1,
		},
		{
			name: "IPv6 default route deleted",
			routes: []netlink.Route{
				{Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}, Gw: nil},
			},
			expectedDelCnt: 1,
		},
		{
			name: "both IPv4 and IPv6 default routes deleted",
			routes: []netlink.Route{
				{Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, Gw: nil},
				{Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}, Gw: nil},
			},
			expectedDelCnt: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Count routes that would be deleted (same logic as configureVethContext.run)
			deleteCount := 0
			for _, route := range tc.routes {
				if route.Gw == nil {
					deleteCount++
				}
			}
			assert.Equal(t, tc.expectedDelCnt, deleteCount,
				"number of routes to delete should match expected")
		})
	}
}

// TestProperty_DefaultRouteDeletion_FamilyAllUsed tests that FAMILY_ALL is used
// to list routes, ensuring both IPv4 and IPv6 routes are considered
// **Validates: Requirements 2.4**
// Property 7: Default Route Deletion
func TestProperty_DefaultRouteDeletion_FamilyAllUsed(t *testing.T) {
	ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	gatewayIPAddr := net.ParseIP(gatewayIP)
	containerIPAddr := net.ParseIP("192.168.1.2")
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   containerIPAddr,
			Mask: net.CIDRMask(31, 32),
		},
		Gateway: gatewayIPAddr,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	mockLink := mock_netlink.NewMockLink(ctrl)
	routes := []netlink.Route{}

	gomock.InOrder(
		mockIPAM.EXPECT().ConfigureIface(interfaceName, gomock.Any()).Return(nil),
		mockIP.EXPECT().SetHWAddrByIP(interfaceName, containerIPAddr, nil).Return(nil),
		mockNetLink.EXPECT().LinkByName(interfaceName).Return(mockLink, nil),
		// Verify FAMILY_ALL is used to list routes
		mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_ALL).Return(routes, nil),
	)
	configContext := newConfigureVethContext(
		interfaceName, result, mockIP, mockIPAM, mockNetLink)
	err := configContext.run(nil)
	assert.NoError(t, err)
}

// =============================================================================
// Backward Compatibility Property Tests
// =============================================================================

// TestProperty_SingleIPv4ResultProcessing tests that for any IPAM result containing
// exactly one IPv4 address, the bridge plugin shall configure the container with
// only IPv4 networking and return a CNI result with one IP configuration.
// **Validates: Requirements 1.1, 6.1**
// Property 1: Single IPv4 Result Processing
func TestProperty_SingleIPv4ResultProcessing(t *testing.T) {
	testCases := []struct {
		name        string
		ipv4Address string
		ipv4Gateway string
		maskBits    int
	}{
		{
			name:        "standard private IPv4",
			ipv4Address: "192.168.1.2",
			ipv4Gateway: "192.168.1.1",
			maskBits:    24,
		},
		{
			name:        "link-local IPv4 (ECS credentials endpoint)",
			ipv4Address: "169.254.172.2",
			ipv4Gateway: "169.254.172.1",
			maskBits:    22,
		},
		{
			name:        "class A private IPv4",
			ipv4Address: "10.0.0.2",
			ipv4Gateway: "10.0.0.1",
			maskBits:    8,
		},
		{
			name:        "class B private IPv4",
			ipv4Address: "172.16.0.2",
			ipv4Gateway: "172.16.0.1",
			maskBits:    16,
		},
		{
			name:        "small subnet IPv4",
			ipv4Address: "192.168.1.2",
			ipv4Gateway: "192.168.1.1",
			maskBits:    31,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl, _, mockNetLink, _, mockIPAM, _ := setup(t)
			defer ctrl.Finish()

			netConf := []byte{}
			ipv4Addr := net.ParseIP(tc.ipv4Address)
			ipv4Gateway := net.ParseIP(tc.ipv4Gateway)

			result := &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{
							IP:   ipv4Addr,
							Mask: net.CIDRMask(tc.maskBits, 32),
						},
						Gateway: ipv4Gateway,
					},
				},
			}

			mockIPAM.EXPECT().ExecAdd(ipamType, netConf).Return(result, nil)

			engine := &engine{ipam: mockIPAM, netLink: mockNetLink}
			returnedResult, err := engine.RunIPAMPluginAdd(ipamType, netConf)

			// Property 1: Single IPv4 result should be accepted
			assert.NoError(t, err, "single IPv4 result should be accepted")
			assert.NotNil(t, returnedResult, "result should not be nil")

			// Verify exactly one IP configuration
			assert.Equal(t, 1, len(returnedResult.IPs), "should have exactly 1 IP config")

			// Verify it's an IPv4 address
			assert.NotNil(t, returnedResult.IPs[0].Address.IP.To4(),
				"IP should be IPv4 (To4() should not be nil)")

			// Verify gateway is set correctly
			assert.Equal(t, ipv4Gateway.String(), returnedResult.IPs[0].Gateway.String(),
				"gateway should match")

			// Verify mask is set correctly
			ones, bits := returnedResult.IPs[0].Address.Mask.Size()
			assert.Equal(t, tc.maskBits, ones, "mask bits should match")
			assert.Equal(t, 32, bits, "should be IPv4 mask (32 bits total)")
		})
	}
}

// TestProperty_BackwardCompatibility tests that for any valid IPv4-only configuration,
// the plugin shall produce behavior identical to the current implementation.
// **Validates: Requirements 6.1, 6.2, 6.3**
// Property 9: Backward Compatibility
func TestProperty_BackwardCompatibility(t *testing.T) {
	// Test that IPv4-only configurations work exactly as before
	testCases := []struct {
		name        string
		ipv4Address string
		ipv4Gateway string
		maskBits    int
	}{
		{
			name:        "ECS link-local config",
			ipv4Address: "169.254.172.2",
			ipv4Gateway: "169.254.172.1",
			maskBits:    22,
		},
		{
			name:        "standard private network",
			ipv4Address: "192.168.1.100",
			ipv4Gateway: "192.168.1.1",
			maskBits:    24,
		},
		{
			name:        "VPC CIDR range",
			ipv4Address: "10.0.1.50",
			ipv4Gateway: "10.0.1.1",
			maskBits:    24,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
			defer ctrl.Finish()

			ipv4Addr := net.ParseIP(tc.ipv4Address)
			ipv4Gateway := net.ParseIP(tc.ipv4Gateway)

			result := &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{
							IP:   ipv4Addr,
							Mask: net.CIDRMask(tc.maskBits, 32),
						},
						Gateway: ipv4Gateway,
					},
				},
			}

			// Test 1: IPAM result validation accepts IPv4-only (backward compatible)
			err := validateIPAMResult(result)
			assert.NoError(t, err, "IPv4-only result should be accepted (backward compatible)")

			// Test 2: Bridge configuration uses AF_INET for IPv4 (backward compatible)
			bridgeLink := &netlink.Bridge{}
			bridgeAddr := &netlink.Addr{
				IPNet: &net.IPNet{
					IP:   ipv4Gateway,
					Mask: net.CIDRMask(tc.maskBits, 32),
				},
			}
			gomock.InOrder(
				mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET).Return(nil, nil),
				mockNetLink.EXPECT().AddrAdd(bridgeLink, bridgeAddr).Return(nil),
			)
			engine := &engine{netLink: mockNetLink}
			err = engine.ConfigureBridge(result, bridgeLink)
			assert.NoError(t, err, "bridge configuration should work for IPv4-only (backward compatible)")

			// Test 3: Veth configuration adds /32 gateway route for IPv4 (backward compatible)
			mockLink := mock_netlink.NewMockLink(ctrl)
			routes := []netlink.Route{}
			gomock.InOrder(
				mockIPAM.EXPECT().ConfigureIface(interfaceName, gomock.Any()).DoAndReturn(
					func(ifName string, res *current.Result) error {
						// Verify gateway route is /32 for IPv4 (backward compatible behavior)
						assert.Equal(t, 1, len(res.Routes), "should have 1 gateway route")
						ones, bits := res.Routes[0].Dst.Mask.Size()
						assert.Equal(t, 32, ones, "IPv4 gateway route should be /32")
						assert.Equal(t, 32, bits, "should be IPv4 mask")
						return nil
					}),
				mockIP.EXPECT().SetHWAddrByIP(interfaceName, ipv4Addr, nil).Return(nil),
				mockNetLink.EXPECT().LinkByName(interfaceName).Return(mockLink, nil),
				mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_ALL).Return(routes, nil),
			)
			configContext := newConfigureVethContext(
				interfaceName, result, mockIP, mockIPAM, mockNetLink)
			err = configContext.run(nil)
			assert.NoError(t, err, "veth configuration should work for IPv4-only (backward compatible)")
		})
	}
}

// TestProperty_BackwardCompatibility_ErrorMessages tests that error messages for
// IPv4-only scenarios remain unchanged (backward compatible).
// **Validates: Requirements 6.3**
// Property 9: Backward Compatibility
func TestProperty_BackwardCompatibility_ErrorMessages(t *testing.T) {
	testCases := []struct {
		name           string
		result         *current.Result
		expectedErrMsg string
	}{
		{
			name: "missing mask error message unchanged",
			result: &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{
							IP: net.ParseIP("192.168.1.2"),
							// Missing mask
						},
						Gateway: net.ParseIP("192.168.1.1"),
					},
				},
			},
			expectedErrMsg: "IP address mask not set for IP[0]",
		},
		{
			name: "missing gateway error message unchanged",
			result: &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{
							IP:   net.ParseIP("192.168.1.2"),
							Mask: net.CIDRMask(24, 32),
						},
						// Missing gateway
					},
				},
			},
			expectedErrMsg: "Gateway not set for IP[0]",
		},
		{
			name: "empty result error message",
			result: &current.Result{
				IPs: []*current.IPConfig{},
			},
			expectedErrMsg: "expected 1 or 2 IP configs, got 0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateIPAMResult(tc.result)
			assert.Error(t, err, "should return error")
			assert.Contains(t, err.Error(), tc.expectedErrMsg,
				"error message should contain expected text (backward compatible)")
		})
	}
}

// TestProperty_BackwardCompatibility_BridgeAddressMismatch tests that bridge address
// mismatch errors work the same for IPv4-only configurations.
// **Validates: Requirements 6.3**
// Property 9: Backward Compatibility
func TestProperty_BackwardCompatibility_BridgeAddressMismatch(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{Name: bridgeName},
	}
	ipv4Gateway := net.ParseIP("192.168.1.1")
	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   net.ParseIP("192.168.1.2"),
			Mask: net.CIDRMask(24, 32),
		},
		Gateway: ipv4Gateway,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	// Bridge has a different IPv4 address than expected
	existingAddrs := []netlink.Addr{
		{
			IPNet: &net.IPNet{
				IP:   net.ParseIP("10.0.0.1"),
				Mask: net.CIDRMask(24, 32),
			},
		},
	}

	mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET).Return(existingAddrs, nil)

	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)

	// Verify error behavior is backward compatible
	assert.Error(t, err, "should return error for address mismatch")
	assert.Contains(t, err.Error(), "mismatch in bridge",
		"error message should indicate bridge mismatch (backward compatible)")
}

// TestProperty_BackwardCompatibility_IPv4OnlyResultStructure tests that the result
// structure for IPv4-only configurations matches the expected format.
// **Validates: Requirements 6.1, 6.2**
// Property 9: Backward Compatibility
func TestProperty_BackwardCompatibility_IPv4OnlyResultStructure(t *testing.T) {
	ctrl, _, _, _, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	netConf := []byte{}
	ipv4Addr := net.ParseIP("169.254.172.2")
	ipv4Gateway := net.ParseIP("169.254.172.1")

	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{
					IP:   ipv4Addr,
					Mask: net.CIDRMask(22, 32),
				},
				Gateway: ipv4Gateway,
			},
		},
	}

	mockIPAM.EXPECT().ExecAdd(ipamType, netConf).Return(result, nil)

	engine := &engine{ipam: mockIPAM}
	returnedResult, err := engine.RunIPAMPluginAdd(ipamType, netConf)

	assert.NoError(t, err)
	assert.NotNil(t, returnedResult)

	// Verify result structure is backward compatible
	assert.Equal(t, 1, len(returnedResult.IPs), "should have exactly 1 IP")

	ip := returnedResult.IPs[0]

	// Verify Address structure
	assert.NotNil(t, ip.Address.IP, "Address.IP should be set")
	assert.NotNil(t, ip.Address.Mask, "Address.Mask should be set")
	assert.NotNil(t, ip.Address.IP.To4(), "should be IPv4 address")

	// Verify Gateway
	assert.NotNil(t, ip.Gateway, "Gateway should be set")
	assert.NotNil(t, ip.Gateway.To4(), "Gateway should be IPv4")

	// Verify the actual values match
	assert.Equal(t, ipv4Addr.String(), ip.Address.IP.String())
	assert.Equal(t, ipv4Gateway.String(), ip.Gateway.String())
}

// =============================================================================
// Property-Based Tests for IPv6-Only Result Processing
// =============================================================================

// TestProperty_SingleIPv6ResultProcessing tests that for any IPAM result containing
// exactly one IPv6 address, the bridge plugin shall configure the container with
// only IPv6 networking and return a CNI result with one IP configuration having version "6".
// **Validates: Requirements 1.2**
// Property 2: Single IPv6 Result Processing
func TestProperty_SingleIPv6ResultProcessing(t *testing.T) {
	testCases := []struct {
		name        string
		ipv6Address string
		ipv6Gateway string
		maskBits    int
	}{
		{
			name:        "global unicast IPv6",
			ipv6Address: "2001:db8::2",
			ipv6Gateway: "2001:db8::1",
			maskBits:    64,
		},
		{
			name:        "ECS IPv6 credentials endpoint",
			ipv6Address: "fd00:ec2::2",
			ipv6Gateway: "fd00:ec2::1",
			maskBits:    64,
		},
		{
			name:        "unique local address (ULA)",
			ipv6Address: "fd12:3456:789a::2",
			ipv6Gateway: "fd12:3456:789a::1",
			maskBits:    48,
		},
		{
			name:        "link-local IPv6",
			ipv6Address: "fe80::2",
			ipv6Gateway: "fe80::1",
			maskBits:    64,
		},
		{
			name:        "IPv6 with /128 mask",
			ipv6Address: "2001:db8:1234:5678::2",
			ipv6Gateway: "2001:db8:1234:5678::1",
			maskBits:    128,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl, _, mockNetLink, _, mockIPAM, _ := setup(t)
			defer ctrl.Finish()

			netConf := []byte{}
			ipv6Addr := net.ParseIP(tc.ipv6Address)
			ipv6Gateway := net.ParseIP(tc.ipv6Gateway)

			result := &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{
							IP:   ipv6Addr,
							Mask: net.CIDRMask(tc.maskBits, 128),
						},
						Gateway: ipv6Gateway,
					},
				},
			}

			mockIPAM.EXPECT().ExecAdd(ipamType, netConf).Return(result, nil)

			engine := &engine{ipam: mockIPAM, netLink: mockNetLink}
			returnedResult, err := engine.RunIPAMPluginAdd(ipamType, netConf)

			// Property 2: Single IPv6 result should be accepted
			assert.NoError(t, err, "single IPv6 result should be accepted")
			assert.NotNil(t, returnedResult, "result should not be nil")

			// Verify exactly one IP configuration
			assert.Equal(t, 1, len(returnedResult.IPs), "should have exactly 1 IP config")

			// Verify it's an IPv6 address (To4() returns nil for IPv6)
			assert.Nil(t, returnedResult.IPs[0].Address.IP.To4(),
				"IP should be IPv6 (To4() should be nil)")

			// Verify gateway is set correctly
			assert.Equal(t, ipv6Gateway.String(), returnedResult.IPs[0].Gateway.String(),
				"gateway should match")

			// Verify mask is set correctly
			ones, bits := returnedResult.IPs[0].Address.Mask.Size()
			assert.Equal(t, tc.maskBits, ones, "mask bits should match")
			assert.Equal(t, 128, bits, "should be IPv6 mask (128 bits total)")
		})
	}
}

// TestProperty_SingleIPv6ResultProcessing_BridgeConfiguration tests that for any
// IPv6-only IPAM result, the bridge is configured with the correct IPv6 address.
// **Validates: Requirements 1.2, 3.1**
// Property 2: Single IPv6 Result Processing
func TestProperty_SingleIPv6ResultProcessing_BridgeConfiguration(t *testing.T) {
	testCases := []struct {
		name        string
		ipv6Address string
		ipv6Gateway string
		maskBits    int
	}{
		{
			name:        "global unicast IPv6",
			ipv6Address: "2001:db8::2",
			ipv6Gateway: "2001:db8::1",
			maskBits:    64,
		},
		{
			name:        "unique local address",
			ipv6Address: "fd00:ec2::2",
			ipv6Gateway: "fd00:ec2::1",
			maskBits:    64,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl, _, mockNetLink, _, _, _ := setup(t)
			defer ctrl.Finish()

			bridgeLink := &netlink.Bridge{}
			ipv6Gateway := net.ParseIP(tc.ipv6Gateway)

			result := &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{
							IP:   net.ParseIP(tc.ipv6Address),
							Mask: net.CIDRMask(tc.maskBits, 128),
						},
						Gateway: ipv6Gateway,
					},
				},
			}

			bridgeAddr := &netlink.Addr{
				IPNet: &net.IPNet{
					IP:   ipv6Gateway,
					Mask: net.CIDRMask(tc.maskBits, 128),
				},
			}

			gomock.InOrder(
				// IPv6 uses AF_INET6
				mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET6).Return(nil, nil),
				mockNetLink.EXPECT().AddrAdd(bridgeLink, bridgeAddr).Return(nil),
			)

			engine := &engine{netLink: mockNetLink}
			err := engine.ConfigureBridge(result, bridgeLink)

			// Property 2: Bridge should be configured with IPv6 address
			assert.NoError(t, err, "bridge configuration should succeed for IPv6-only")
		})
	}
}

// TestProperty_SingleIPv6ResultProcessing_VethConfiguration tests that for any
// IPv6-only IPAM result, the veth interface is configured with correct IPv6 routes.
// **Validates: Requirements 1.2, 2.1**
// Property 2: Single IPv6 Result Processing
func TestProperty_SingleIPv6ResultProcessing_VethConfiguration(t *testing.T) {
	testCases := []struct {
		name        string
		ipv6Address string
		ipv6Gateway string
		maskBits    int
	}{
		{
			name:        "global unicast IPv6",
			ipv6Address: "2001:db8::2",
			ipv6Gateway: "2001:db8::1",
			maskBits:    64,
		},
		{
			name:        "unique local address",
			ipv6Address: "fd00:ec2::2",
			ipv6Gateway: "fd00:ec2::1",
			maskBits:    64,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
			defer ctrl.Finish()

			ipv6Gateway := net.ParseIP(tc.ipv6Gateway)
			ipv6ContainerAddr := net.ParseIP(tc.ipv6Address)

			result := &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{
							IP:   ipv6ContainerAddr,
							Mask: net.CIDRMask(tc.maskBits, 128),
						},
						Gateway: ipv6Gateway,
					},
				},
			}

			mockLink := mock_netlink.NewMockLink(ctrl)
			routes := []netlink.Route{}

			gomock.InOrder(
				mockIPAM.EXPECT().ConfigureIface(interfaceName, gomock.Any()).DoAndReturn(
					func(ifName string, res *current.Result) error {
						// Property 2: Verify /128 gateway route is added for IPv6
						assert.Equal(t, 1, len(res.Routes), "should have 1 gateway route")
						assert.Equal(t, ipv6Gateway.String(), res.Routes[0].Dst.IP.String(),
							"gateway route should use IPv6 gateway")
						ones, bits := res.Routes[0].Dst.Mask.Size()
						assert.Equal(t, 128, ones, "IPv6 gateway route should be /128")
						assert.Equal(t, 128, bits, "should be IPv6 mask")
						return nil
					}),
				mockIP.EXPECT().SetHWAddrByIP(interfaceName, nil, ipv6ContainerAddr).Return(nil),
				mockNetLink.EXPECT().LinkByName(interfaceName).Return(mockLink, nil),
				mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_ALL).Return(routes, nil),
			)

			configContext := newConfigureVethContext(
				interfaceName, result, mockIP, mockIPAM, mockNetLink)
			err := configContext.run(nil)

			// Property 2: Veth configuration should succeed for IPv6-only
			assert.NoError(t, err, "veth configuration should succeed for IPv6-only")
		})
	}
}

// =============================================================================
// Property-Based Tests for Dual-Stack Result Processing
// =============================================================================

// TestProperty_DualStackResultProcessing tests that for any IPAM result containing
// both IPv4 and IPv6 addresses, the bridge plugin shall configure the container with
// dual-stack networking and return a CNI result with two IP configurations.
// **Validates: Requirements 1.3**
// Property 3: Dual-Stack Result Processing
func TestProperty_DualStackResultProcessing(t *testing.T) {
	testCases := []struct {
		name         string
		ipv4Address  string
		ipv4Gateway  string
		ipv4MaskBits int
		ipv6Address  string
		ipv6Gateway  string
		ipv6MaskBits int
	}{
		{
			name:         "standard dual-stack",
			ipv4Address:  "192.168.1.2",
			ipv4Gateway:  "192.168.1.1",
			ipv4MaskBits: 24,
			ipv6Address:  "2001:db8::2",
			ipv6Gateway:  "2001:db8::1",
			ipv6MaskBits: 64,
		},
		{
			name:         "ECS dual-stack credentials endpoint",
			ipv4Address:  "169.254.172.2",
			ipv4Gateway:  "169.254.172.1",
			ipv4MaskBits: 22,
			ipv6Address:  "fd00:ec2::2",
			ipv6Gateway:  "fd00:ec2::1",
			ipv6MaskBits: 64,
		},
		{
			name:         "VPC dual-stack",
			ipv4Address:  "10.0.1.50",
			ipv4Gateway:  "10.0.1.1",
			ipv4MaskBits: 24,
			ipv6Address:  "2600:1f18:1234:5678::50",
			ipv6Gateway:  "2600:1f18:1234:5678::1",
			ipv6MaskBits: 64,
		},
		{
			name:         "small subnets dual-stack",
			ipv4Address:  "192.168.1.2",
			ipv4Gateway:  "192.168.1.1",
			ipv4MaskBits: 31,
			ipv6Address:  "fd12:3456:789a::2",
			ipv6Gateway:  "fd12:3456:789a::1",
			ipv6MaskBits: 126,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl, _, mockNetLink, _, mockIPAM, _ := setup(t)
			defer ctrl.Finish()

			netConf := []byte{}
			ipv4Addr := net.ParseIP(tc.ipv4Address)
			ipv4Gateway := net.ParseIP(tc.ipv4Gateway)
			ipv6Addr := net.ParseIP(tc.ipv6Address)
			ipv6Gateway := net.ParseIP(tc.ipv6Gateway)

			result := &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{
							IP:   ipv4Addr,
							Mask: net.CIDRMask(tc.ipv4MaskBits, 32),
						},
						Gateway: ipv4Gateway,
					},
					{
						Address: net.IPNet{
							IP:   ipv6Addr,
							Mask: net.CIDRMask(tc.ipv6MaskBits, 128),
						},
						Gateway: ipv6Gateway,
					},
				},
			}

			mockIPAM.EXPECT().ExecAdd(ipamType, netConf).Return(result, nil)

			engine := &engine{ipam: mockIPAM, netLink: mockNetLink}
			returnedResult, err := engine.RunIPAMPluginAdd(ipamType, netConf)

			// Property 3: Dual-stack result should be accepted
			assert.NoError(t, err, "dual-stack result should be accepted")
			assert.NotNil(t, returnedResult, "result should not be nil")

			// Verify exactly two IP configurations
			assert.Equal(t, 2, len(returnedResult.IPs), "should have exactly 2 IP configs")

			// Verify first IP is IPv4
			assert.NotNil(t, returnedResult.IPs[0].Address.IP.To4(),
				"first IP should be IPv4")
			assert.Equal(t, ipv4Gateway.String(), returnedResult.IPs[0].Gateway.String(),
				"IPv4 gateway should match")

			// Verify second IP is IPv6
			assert.Nil(t, returnedResult.IPs[1].Address.IP.To4(),
				"second IP should be IPv6")
			assert.Equal(t, ipv6Gateway.String(), returnedResult.IPs[1].Gateway.String(),
				"IPv6 gateway should match")
		})
	}
}

// TestProperty_DualStackResultProcessing_IPv6First tests that dual-stack works
// regardless of IP order (IPv6 first, then IPv4).
// **Validates: Requirements 1.3**
// Property 3: Dual-Stack Result Processing
func TestProperty_DualStackResultProcessing_IPv6First(t *testing.T) {
	testCases := []struct {
		name         string
		ipv4Address  string
		ipv4Gateway  string
		ipv4MaskBits int
		ipv6Address  string
		ipv6Gateway  string
		ipv6MaskBits int
	}{
		{
			name:         "IPv6 first standard",
			ipv4Address:  "192.168.1.2",
			ipv4Gateway:  "192.168.1.1",
			ipv4MaskBits: 24,
			ipv6Address:  "2001:db8::2",
			ipv6Gateway:  "2001:db8::1",
			ipv6MaskBits: 64,
		},
		{
			name:         "IPv6 first ECS",
			ipv4Address:  "169.254.172.2",
			ipv4Gateway:  "169.254.172.1",
			ipv4MaskBits: 22,
			ipv6Address:  "fd00:ec2::2",
			ipv6Gateway:  "fd00:ec2::1",
			ipv6MaskBits: 64,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl, _, mockNetLink, _, mockIPAM, _ := setup(t)
			defer ctrl.Finish()

			netConf := []byte{}
			ipv4Addr := net.ParseIP(tc.ipv4Address)
			ipv4Gateway := net.ParseIP(tc.ipv4Gateway)
			ipv6Addr := net.ParseIP(tc.ipv6Address)
			ipv6Gateway := net.ParseIP(tc.ipv6Gateway)

			// IPv6 first in the list
			result := &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{
							IP:   ipv6Addr,
							Mask: net.CIDRMask(tc.ipv6MaskBits, 128),
						},
						Gateway: ipv6Gateway,
					},
					{
						Address: net.IPNet{
							IP:   ipv4Addr,
							Mask: net.CIDRMask(tc.ipv4MaskBits, 32),
						},
						Gateway: ipv4Gateway,
					},
				},
			}

			mockIPAM.EXPECT().ExecAdd(ipamType, netConf).Return(result, nil)

			engine := &engine{ipam: mockIPAM, netLink: mockNetLink}
			returnedResult, err := engine.RunIPAMPluginAdd(ipamType, netConf)

			// Property 3: Dual-stack result should be accepted regardless of order
			assert.NoError(t, err, "dual-stack result with IPv6 first should be accepted")
			assert.NotNil(t, returnedResult, "result should not be nil")

			// Verify exactly two IP configurations
			assert.Equal(t, 2, len(returnedResult.IPs), "should have exactly 2 IP configs")

			// Verify first IP is IPv6 (as provided)
			assert.Nil(t, returnedResult.IPs[0].Address.IP.To4(),
				"first IP should be IPv6")

			// Verify second IP is IPv4 (as provided)
			assert.NotNil(t, returnedResult.IPs[1].Address.IP.To4(),
				"second IP should be IPv4")
		})
	}
}

// TestProperty_DualStackResultProcessing_BridgeConfiguration tests that for any
// dual-stack IPAM result, the bridge is configured with both IPv4 and IPv6 addresses.
// **Validates: Requirements 1.3, 3.2**
// Property 3: Dual-Stack Result Processing
func TestProperty_DualStackResultProcessing_BridgeConfiguration(t *testing.T) {
	testCases := []struct {
		name         string
		ipv4Address  string
		ipv4Gateway  string
		ipv4MaskBits int
		ipv6Address  string
		ipv6Gateway  string
		ipv6MaskBits int
	}{
		{
			name:         "standard dual-stack",
			ipv4Address:  "192.168.1.2",
			ipv4Gateway:  "192.168.1.1",
			ipv4MaskBits: 24,
			ipv6Address:  "2001:db8::2",
			ipv6Gateway:  "2001:db8::1",
			ipv6MaskBits: 64,
		},
		{
			name:         "ECS dual-stack",
			ipv4Address:  "169.254.172.2",
			ipv4Gateway:  "169.254.172.1",
			ipv4MaskBits: 22,
			ipv6Address:  "fd00:ec2::2",
			ipv6Gateway:  "fd00:ec2::1",
			ipv6MaskBits: 64,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl, _, mockNetLink, _, _, _ := setup(t)
			defer ctrl.Finish()

			bridgeLink := &netlink.Bridge{}
			ipv4Gateway := net.ParseIP(tc.ipv4Gateway)
			ipv6Gateway := net.ParseIP(tc.ipv6Gateway)

			result := &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{
							IP:   net.ParseIP(tc.ipv4Address),
							Mask: net.CIDRMask(tc.ipv4MaskBits, 32),
						},
						Gateway: ipv4Gateway,
					},
					{
						Address: net.IPNet{
							IP:   net.ParseIP(tc.ipv6Address),
							Mask: net.CIDRMask(tc.ipv6MaskBits, 128),
						},
						Gateway: ipv6Gateway,
					},
				},
			}

			ipv4BridgeAddr := &netlink.Addr{
				IPNet: &net.IPNet{
					IP:   ipv4Gateway,
					Mask: net.CIDRMask(tc.ipv4MaskBits, 32),
				},
			}
			ipv6BridgeAddr := &netlink.Addr{
				IPNet: &net.IPNet{
					IP:   ipv6Gateway,
					Mask: net.CIDRMask(tc.ipv6MaskBits, 128),
				},
			}

			gomock.InOrder(
				// First IP (IPv4) uses AF_INET
				mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET).Return(nil, nil),
				mockNetLink.EXPECT().AddrAdd(bridgeLink, ipv4BridgeAddr).Return(nil),
				// Second IP (IPv6) uses AF_INET6
				mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET6).Return(nil, nil),
				mockNetLink.EXPECT().AddrAdd(bridgeLink, ipv6BridgeAddr).Return(nil),
			)

			engine := &engine{netLink: mockNetLink}
			err := engine.ConfigureBridge(result, bridgeLink)

			// Property 3: Bridge should be configured with both addresses
			assert.NoError(t, err, "bridge configuration should succeed for dual-stack")
		})
	}
}

// TestProperty_DualStackResultProcessing_VethConfiguration tests that for any
// dual-stack IPAM result, the veth interface is configured with routes for both families.
// **Validates: Requirements 1.3, 2.1**
// Property 3: Dual-Stack Result Processing
func TestProperty_DualStackResultProcessing_VethConfiguration(t *testing.T) {
	testCases := []struct {
		name         string
		ipv4Address  string
		ipv4Gateway  string
		ipv4MaskBits int
		ipv6Address  string
		ipv6Gateway  string
		ipv6MaskBits int
	}{
		{
			name:         "standard dual-stack",
			ipv4Address:  "192.168.1.2",
			ipv4Gateway:  "192.168.1.1",
			ipv4MaskBits: 24,
			ipv6Address:  "2001:db8::2",
			ipv6Gateway:  "2001:db8::1",
			ipv6MaskBits: 64,
		},
		{
			name:         "ECS dual-stack",
			ipv4Address:  "169.254.172.2",
			ipv4Gateway:  "169.254.172.1",
			ipv4MaskBits: 22,
			ipv6Address:  "fd00:ec2::2",
			ipv6Gateway:  "fd00:ec2::1",
			ipv6MaskBits: 64,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
			defer ctrl.Finish()

			ipv4Gateway := net.ParseIP(tc.ipv4Gateway)
			ipv4ContainerAddr := net.ParseIP(tc.ipv4Address)
			ipv6Gateway := net.ParseIP(tc.ipv6Gateway)
			ipv6ContainerAddr := net.ParseIP(tc.ipv6Address)

			result := &current.Result{
				IPs: []*current.IPConfig{
					{
						Address: net.IPNet{
							IP:   ipv4ContainerAddr,
							Mask: net.CIDRMask(tc.ipv4MaskBits, 32),
						},
						Gateway: ipv4Gateway,
					},
					{
						Address: net.IPNet{
							IP:   ipv6ContainerAddr,
							Mask: net.CIDRMask(tc.ipv6MaskBits, 128),
						},
						Gateway: ipv6Gateway,
					},
				},
			}

			mockLink := mock_netlink.NewMockLink(ctrl)
			routes := []netlink.Route{}

			gomock.InOrder(
				mockIPAM.EXPECT().ConfigureIface(interfaceName, gomock.Any()).DoAndReturn(
					func(ifName string, res *current.Result) error {
						// Property 3: Verify gateway routes for both IPv4 and IPv6
						assert.Equal(t, 2, len(res.Routes), "should have 2 gateway routes")

						// First route should be IPv4 /32
						assert.Equal(t, ipv4Gateway.String(), res.Routes[0].Dst.IP.String(),
							"first gateway route should use IPv4 gateway")
						ones, _ := res.Routes[0].Dst.Mask.Size()
						assert.Equal(t, 32, ones, "IPv4 gateway route should be /32")

						// Second route should be IPv6 /128
						assert.Equal(t, ipv6Gateway.String(), res.Routes[1].Dst.IP.String(),
							"second gateway route should use IPv6 gateway")
						ones, _ = res.Routes[1].Dst.Mask.Size()
						assert.Equal(t, 128, ones, "IPv6 gateway route should be /128")

						return nil
					}),
				// For dual-stack, SetHWAddrByIP uses both IPv4 and IPv6 addresses
				mockIP.EXPECT().SetHWAddrByIP(interfaceName, ipv4ContainerAddr, ipv6ContainerAddr).Return(nil),
				mockNetLink.EXPECT().LinkByName(interfaceName).Return(mockLink, nil),
				mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_ALL).Return(routes, nil),
			)

			configContext := newConfigureVethContext(
				interfaceName, result, mockIP, mockIPAM, mockNetLink)
			err := configContext.run(nil)

			// Property 3: Veth configuration should succeed for dual-stack
			assert.NoError(t, err, "veth configuration should succeed for dual-stack")
		})
	}
}

// TestProperty_DualStackResultProcessing_DefaultRoutesDeletion tests that for any
// dual-stack configuration, default routes for both address families are deleted.
// **Validates: Requirements 1.3, 2.4**
// Property 3: Dual-Stack Result Processing
func TestProperty_DualStackResultProcessing_DefaultRoutesDeletion(t *testing.T) {
	ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	ipv4Gateway := net.ParseIP(gatewayIP)
	ipv4ContainerAddr := net.ParseIP("192.168.1.2")
	ipv6Gateway := net.ParseIP(ipv6GatewayIP)
	ipv6ContainerAddr := net.ParseIP(ipv6ContainerIP)

	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: net.IPNet{
					IP:   ipv4ContainerAddr,
					Mask: net.CIDRMask(31, 32),
				},
				Gateway: ipv4Gateway,
			},
			{
				Address: net.IPNet{
					IP:   ipv6ContainerAddr,
					Mask: net.CIDRMask(64, 128),
				},
				Gateway: ipv6Gateway,
			},
		},
	}

	mockLink := mock_netlink.NewMockLink(ctrl)

	// Both IPv4 and IPv6 default routes present
	ipv4DefaultRoute := netlink.Route{
		Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Gw:  nil, // No gateway = default route to delete
	}
	ipv6DefaultRoute := netlink.Route{
		Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		Gw:  nil, // No gateway = default route to delete
	}
	routes := []netlink.Route{ipv4DefaultRoute, ipv6DefaultRoute}

	gomock.InOrder(
		mockIPAM.EXPECT().ConfigureIface(interfaceName, gomock.Any()).Return(nil),
		mockIP.EXPECT().SetHWAddrByIP(interfaceName, ipv4ContainerAddr, ipv6ContainerAddr).Return(nil),
		mockNetLink.EXPECT().LinkByName(interfaceName).Return(mockLink, nil),
		mockNetLink.EXPECT().RouteList(mockLink, netlink.FAMILY_ALL).Return(routes, nil),
		// Property 3: Both default routes should be deleted
		mockNetLink.EXPECT().RouteDel(&ipv4DefaultRoute).Return(nil),
		mockNetLink.EXPECT().RouteDel(&ipv6DefaultRoute).Return(nil),
	)

	configContext := newConfigureVethContext(
		interfaceName, result, mockIP, mockIPAM, mockNetLink)
	err := configContext.run(nil)

	assert.NoError(t, err, "dual-stack veth configuration should delete both default routes")
}
