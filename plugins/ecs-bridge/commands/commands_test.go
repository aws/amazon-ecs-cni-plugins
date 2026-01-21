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

package commands

import (
	"errors"
	"net"
	"testing"

	mock_engine "github.com/aws/amazon-ecs-cni-plugins/plugins/ecs-bridge/engine/mocks"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

const (
	bridgeName    = "ecs-br0"
	defaultMTU    = 1500
	nsName        = "ecs-eni"
	interfaceName = "ecs-veth0"
	hostVethName  = "ecs-host-veth0"
	ipamType      = "ecs-ipam"
	mac           = "01:23:45:67:89:ab"
)

var conf = &skel.CmdArgs{
	StdinData: []byte(`{"bridge":"` + bridgeName +
		`", "ipam":{"type": "` + ipamType + `"}}`),
	Netns:  nsName,
	IfName: interfaceName,
}

var emptyConf = &skel.CmdArgs{
	StdinData: []byte(""),
	Netns:     nsName,
}

var macHWAddr net.HardwareAddr

func init() {
	macHWAddr, _ = net.ParseMAC(mac)
}

// TODO: Add integration tests for command.Add commands.Del

func TestAddConfError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)

	err := add(emptyConf, mockEngine)
	assert.Error(t, err)
}

func TestAddCreateBridgeError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	mockEngine.EXPECT().CreateBridge(bridgeName, defaultMTU).Return(nil, errors.New("error"))
	err := add(conf, mockEngine)
	assert.Error(t, err)
}

func TestAddCreateVethPairError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	gomock.InOrder(
		mockEngine.EXPECT().CreateBridge(bridgeName, defaultMTU).Return(nil, nil),
		mockEngine.EXPECT().CreateVethPair(nsName, defaultMTU, interfaceName).Return(nil, "", errors.New("error")),
	)
	err := add(conf, mockEngine)
	assert.Error(t, err)
}

func TestAddAttachHostVethInterfaceToBridgeError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	bridgeLink := &netlink.Bridge{}
	gomock.InOrder(
		mockEngine.EXPECT().CreateBridge(bridgeName, defaultMTU).Return(bridgeLink, nil),
		mockEngine.EXPECT().CreateVethPair(nsName, defaultMTU, interfaceName).Return(nil, hostVethName, nil),
		mockEngine.EXPECT().AttachHostVethInterfaceToBridge(hostVethName, bridgeLink).Return(nil, errors.New("error")),
	)
	err := add(conf, mockEngine)
	assert.Error(t, err)
}

func TestAddRunIPAMPlginAddError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	bridgeLink := &netlink.Bridge{}
	gomock.InOrder(
		mockEngine.EXPECT().CreateBridge(bridgeName, defaultMTU).Return(bridgeLink, nil),
		mockEngine.EXPECT().CreateVethPair(nsName, defaultMTU, interfaceName).Return(nil, hostVethName, nil),
		mockEngine.EXPECT().AttachHostVethInterfaceToBridge(hostVethName, bridgeLink).Return(nil, nil),
		mockEngine.EXPECT().RunIPAMPluginAdd(ipamType, conf.StdinData).Return(nil, errors.New("error")),
	)
	err := add(conf, mockEngine)
	assert.Error(t, err)
}

func TestAddConfigureContainerVethInterfaceError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	bridgeLink := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name:         bridgeName,
			HardwareAddr: macHWAddr,
		},
	}

	result := &current.Result{
		IPs: []*current.IPConfig{
			&current.IPConfig{},
		},
	}
	containerVethInterface := &current.Interface{}
	hostVethInterface := &current.Interface{}
	gomock.InOrder(
		mockEngine.EXPECT().CreateBridge(bridgeName, defaultMTU).Return(bridgeLink, nil),
		mockEngine.EXPECT().CreateVethPair(nsName, defaultMTU, interfaceName).Return(containerVethInterface, hostVethName, nil),
		mockEngine.EXPECT().AttachHostVethInterfaceToBridge(hostVethName, bridgeLink).Return(hostVethInterface, nil),
		mockEngine.EXPECT().RunIPAMPluginAdd(ipamType, conf.StdinData).Return(result, nil),
		mockEngine.EXPECT().ConfigureContainerVethInterface(nsName, result, interfaceName).Do(
			func(netns string, res *current.Result, ifName string) {
				assert.NotEmpty(t, res)
				assert.Equal(t, 3, len(res.Interfaces))
				assert.Equal(t, 2, res.IPs[0].Interface)
				bridge := res.Interfaces[0]
				assert.Equal(t, bridgeName, bridge.Name)
				assert.Equal(t, mac, bridge.Mac)
			}).Return(errors.New("error")),
	)
	err := add(conf, mockEngine)
	assert.Error(t, err)
}

func TestAddConfigureBridgeError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	bridgeLink := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name:         bridgeName,
			HardwareAddr: macHWAddr,
		},
	}

	result := &current.Result{
		IPs: []*current.IPConfig{
			&current.IPConfig{},
		},
	}
	containerVethInterface := &current.Interface{}
	hostVethInterface := &current.Interface{}
	gomock.InOrder(
		mockEngine.EXPECT().CreateBridge(bridgeName, defaultMTU).Return(bridgeLink, nil),
		mockEngine.EXPECT().CreateVethPair(nsName, defaultMTU, interfaceName).Return(containerVethInterface, hostVethName, nil),
		mockEngine.EXPECT().AttachHostVethInterfaceToBridge(hostVethName, bridgeLink).Return(hostVethInterface, nil),
		mockEngine.EXPECT().RunIPAMPluginAdd(ipamType, conf.StdinData).Return(result, nil),
		mockEngine.EXPECT().ConfigureContainerVethInterface(nsName, result, interfaceName).Return(nil),
		mockEngine.EXPECT().ConfigureBridge(result, bridgeLink).Return(errors.New("error")),
	)
	err := add(conf, mockEngine)
	assert.Error(t, err)

}

func TestAddSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	bridgeLink := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name:         bridgeName,
			HardwareAddr: macHWAddr,
		},
	}

	result := &current.Result{
		IPs: []*current.IPConfig{
			&current.IPConfig{},
		},
	}
	containerVethInterface := &current.Interface{}
	hostVethInterface := &current.Interface{}
	gomock.InOrder(
		mockEngine.EXPECT().CreateBridge(bridgeName, defaultMTU).Return(bridgeLink, nil),
		mockEngine.EXPECT().CreateVethPair(nsName, defaultMTU, interfaceName).Return(containerVethInterface, hostVethName, nil),
		mockEngine.EXPECT().AttachHostVethInterfaceToBridge(hostVethName, bridgeLink).Return(hostVethInterface, nil),
		mockEngine.EXPECT().RunIPAMPluginAdd(ipamType, conf.StdinData).Return(result, nil),
		mockEngine.EXPECT().ConfigureContainerVethInterface(nsName, result, interfaceName).Do(
			func(netns string, res *current.Result, ifName string) {
				assert.NotEmpty(t, res)
				assert.Equal(t, 3, len(res.Interfaces))
				assert.Equal(t, 2, res.IPs[0].Interface)
				bridge := res.Interfaces[0]
				assert.Equal(t, bridgeName, bridge.Name)
				assert.Equal(t, mac, bridge.Mac)
			}).Return(nil),
		mockEngine.EXPECT().ConfigureBridge(result, bridgeLink).Return(nil),
	)
	err := add(conf, mockEngine)
	assert.NoError(t, err)
}

func TestDelNewConfError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	err := del(emptyConf, mockEngine)
	assert.Error(t, err)
}

func TestDelRunIPAMPluginDelError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	mockEngine.EXPECT().RunIPAMPluginDel(ipamType, conf.StdinData).Return(errors.New("error"))
	mockEngine.EXPECT().DeleteVeth(nsName, interfaceName).Return(nil)
	err := del(conf, mockEngine)
	// the final error that gets returned is from DeleteVeth - we log the error for IPAM delete and then carry on
	assert.NoError(t, err)
}

func TestDelDeleteVethError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	gomock.InOrder(
		mockEngine.EXPECT().RunIPAMPluginDel(ipamType, conf.StdinData).Return(nil),
		mockEngine.EXPECT().DeleteVeth(nsName, interfaceName).Return(errors.New("error")),
	)
	err := del(conf, mockEngine)
	assert.Error(t, err)
}

func TestDelSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	gomock.InOrder(
		mockEngine.EXPECT().RunIPAMPluginDel(ipamType, conf.StdinData).Return(nil),
		mockEngine.EXPECT().DeleteVeth(nsName, interfaceName).Return(nil),
	)
	err := del(conf, mockEngine)
	assert.NoError(t, err)
}

// TestAddWithSingleIPv4Result tests ADD with a single IPv4 result
// Validates: Requirements 4.3, 5.2 - Interface index assignment for IPv4
func TestAddWithSingleIPv4Result(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	bridgeLink := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name:         bridgeName,
			HardwareAddr: macHWAddr,
		},
	}

	_, ipv4Net, _ := net.ParseCIDR("169.254.172.2/22")
	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: *ipv4Net,
				Gateway: net.ParseIP("169.254.172.1"),
			},
		},
	}
	containerVethInterface := &current.Interface{}
	hostVethInterface := &current.Interface{}
	gomock.InOrder(
		mockEngine.EXPECT().CreateBridge(bridgeName, defaultMTU).Return(bridgeLink, nil),
		mockEngine.EXPECT().CreateVethPair(nsName, defaultMTU, interfaceName).Return(containerVethInterface, hostVethName, nil),
		mockEngine.EXPECT().AttachHostVethInterfaceToBridge(hostVethName, bridgeLink).Return(hostVethInterface, nil),
		mockEngine.EXPECT().RunIPAMPluginAdd(ipamType, conf.StdinData).Return(result, nil),
		mockEngine.EXPECT().ConfigureContainerVethInterface(nsName, result, interfaceName).Do(
			func(netns string, res *current.Result, ifName string) {
				assert.NotEmpty(t, res)
				assert.Equal(t, 3, len(res.Interfaces))
				// Verify single IPv4 IP has interface index set to 2 (container veth)
				assert.Equal(t, 1, len(res.IPs))
				assert.Equal(t, 2, res.IPs[0].Interface)
				// Verify it's an IPv4 address
				assert.NotNil(t, res.IPs[0].Address.IP.To4())
			}).Return(nil),
		mockEngine.EXPECT().ConfigureBridge(result, bridgeLink).Return(nil),
	)
	err := add(conf, mockEngine)
	assert.NoError(t, err)
}

// TestAddWithSingleIPv6Result tests ADD with a single IPv6 result
// Validates: Requirements 4.3, 5.2 - Interface index assignment for IPv6
func TestAddWithSingleIPv6Result(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	bridgeLink := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name:         bridgeName,
			HardwareAddr: macHWAddr,
		},
	}

	_, ipv6Net, _ := net.ParseCIDR("2001:db8::2/64")
	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: *ipv6Net,
				Gateway: net.ParseIP("2001:db8::1"),
			},
		},
	}
	containerVethInterface := &current.Interface{}
	hostVethInterface := &current.Interface{}
	gomock.InOrder(
		mockEngine.EXPECT().CreateBridge(bridgeName, defaultMTU).Return(bridgeLink, nil),
		mockEngine.EXPECT().CreateVethPair(nsName, defaultMTU, interfaceName).Return(containerVethInterface, hostVethName, nil),
		mockEngine.EXPECT().AttachHostVethInterfaceToBridge(hostVethName, bridgeLink).Return(hostVethInterface, nil),
		mockEngine.EXPECT().RunIPAMPluginAdd(ipamType, conf.StdinData).Return(result, nil),
		mockEngine.EXPECT().ConfigureContainerVethInterface(nsName, result, interfaceName).Do(
			func(netns string, res *current.Result, ifName string) {
				assert.NotEmpty(t, res)
				assert.Equal(t, 3, len(res.Interfaces))
				// Verify single IPv6 IP has interface index set to 2 (container veth)
				assert.Equal(t, 1, len(res.IPs))
				assert.Equal(t, 2, res.IPs[0].Interface)
				// Verify it's an IPv6 address (To4() returns nil for IPv6)
				assert.Nil(t, res.IPs[0].Address.IP.To4())
			}).Return(nil),
		mockEngine.EXPECT().ConfigureBridge(result, bridgeLink).Return(nil),
	)
	err := add(conf, mockEngine)
	assert.NoError(t, err)
}

// TestAddWithDualStackResult tests ADD with both IPv4 and IPv6 results
// Validates: Requirements 4.3, 5.2 - Interface index assignment for dual-stack
// **Property 6: Interface Index Assignment**
func TestAddWithDualStackResult(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	bridgeLink := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name:         bridgeName,
			HardwareAddr: macHWAddr,
		},
	}

	_, ipv4Net, _ := net.ParseCIDR("169.254.172.2/22")
	_, ipv6Net, _ := net.ParseCIDR("2001:db8::2/64")
	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: *ipv4Net,
				Gateway: net.ParseIP("169.254.172.1"),
			},
			{
				Address: *ipv6Net,
				Gateway: net.ParseIP("2001:db8::1"),
			},
		},
	}
	containerVethInterface := &current.Interface{}
	hostVethInterface := &current.Interface{}
	gomock.InOrder(
		mockEngine.EXPECT().CreateBridge(bridgeName, defaultMTU).Return(bridgeLink, nil),
		mockEngine.EXPECT().CreateVethPair(nsName, defaultMTU, interfaceName).Return(containerVethInterface, hostVethName, nil),
		mockEngine.EXPECT().AttachHostVethInterfaceToBridge(hostVethName, bridgeLink).Return(hostVethInterface, nil),
		mockEngine.EXPECT().RunIPAMPluginAdd(ipamType, conf.StdinData).Return(result, nil),
		mockEngine.EXPECT().ConfigureContainerVethInterface(nsName, result, interfaceName).Do(
			func(netns string, res *current.Result, ifName string) {
				assert.NotEmpty(t, res)
				assert.Equal(t, 3, len(res.Interfaces))
				// Verify both IPs have interface index set to 2 (container veth)
				assert.Equal(t, 2, len(res.IPs))
				for i, ip := range res.IPs {
					assert.Equal(t, 2, ip.Interface, "IP[%d] should have interface index 2", i)
				}
				// Verify first is IPv4
				assert.NotNil(t, res.IPs[0].Address.IP.To4(), "First IP should be IPv4")
				// Verify second is IPv6
				assert.Nil(t, res.IPs[1].Address.IP.To4(), "Second IP should be IPv6")
			}).Return(nil),
		mockEngine.EXPECT().ConfigureBridge(result, bridgeLink).Return(nil),
	)
	err := add(conf, mockEngine)
	assert.NoError(t, err)
}

// TestAddInterfaceIndexAssignmentProperty tests that interface indices are set correctly
// for all IP configurations regardless of count
// **Property 6: Interface Index Assignment**
// Validates: Requirements 4.3, 5.2
func TestAddInterfaceIndexAssignmentProperty(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	bridgeLink := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name:         bridgeName,
			HardwareAddr: macHWAddr,
		},
	}

	// Test with dual-stack to verify all IPs get the correct interface index
	_, ipv4Net, _ := net.ParseCIDR("10.0.0.2/24")
	_, ipv6Net, _ := net.ParseCIDR("fd00::2/64")
	result := &current.Result{
		IPs: []*current.IPConfig{
			{
				Address: *ipv4Net,
				Gateway: net.ParseIP("10.0.0.1"),
			},
			{
				Address: *ipv6Net,
				Gateway: net.ParseIP("fd00::1"),
			},
		},
	}
	containerVethInterface := &current.Interface{}
	hostVethInterface := &current.Interface{}
	gomock.InOrder(
		mockEngine.EXPECT().CreateBridge(bridgeName, defaultMTU).Return(bridgeLink, nil),
		mockEngine.EXPECT().CreateVethPair(nsName, defaultMTU, interfaceName).Return(containerVethInterface, hostVethName, nil),
		mockEngine.EXPECT().AttachHostVethInterfaceToBridge(hostVethName, bridgeLink).Return(hostVethInterface, nil),
		mockEngine.EXPECT().RunIPAMPluginAdd(ipamType, conf.StdinData).Return(result, nil),
		mockEngine.EXPECT().ConfigureContainerVethInterface(nsName, result, interfaceName).Do(
			func(netns string, res *current.Result, ifName string) {
				// Property: For any IP configuration in the IPAM result,
				// the bridge plugin shall set the interface index to point
				// to the container veth interface (index 2)
				for i, ip := range res.IPs {
					assert.Equal(t, 2, ip.Interface,
						"IP[%d] interface index should be 2 (container veth)", i)
				}
			}).Return(nil),
		mockEngine.EXPECT().ConfigureBridge(result, bridgeLink).Return(nil),
	)
	err := add(conf, mockEngine)
	assert.NoError(t, err)
}
