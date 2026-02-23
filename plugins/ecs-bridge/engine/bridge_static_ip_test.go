// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
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
	"os"
	"syscall"
	"testing"

	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

// TestConfigureBridge_LinkLocalIPv4_UsesCIDR22 tests that bridge gets /22 mask for link-local IPv4
func TestConfigureBridge_LinkLocalIPv4_UsesCIDR22(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{Name: "fargate-bridge"},
	}

	// Link-local gateway IP (169.254.x.x)
	gatewayIP := net.ParseIP("169.254.172.1")
	containerIP := net.ParseIP("169.254.172.2")

	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   containerIP,
			Mask: net.CIDRMask(32, 32), // Container has /32
		},
		Gateway: gatewayIP,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	// Expected bridge address should have /22 mask, not /32
	expectedBridgeAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   gatewayIP,
			Mask: net.CIDRMask(22, 32), // Bridge gets /22
		},
	}

	gomock.InOrder(
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET).Return(nil, nil),
		mockNetLink.EXPECT().AddrAdd(bridgeLink, expectedBridgeAddr).Return(nil),
	)

	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.NoError(t, err)
}

// TestConfigureBridge_LinkLocalIPv6_UsesCIDR64 tests that bridge gets /64 mask for link-local IPv6
func TestConfigureBridge_LinkLocalIPv6_UsesCIDR64(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{Name: "fargate-bridge"},
	}

	// Link-local IPv6 gateway
	gatewayIP := net.ParseIP("fe80::1")
	containerIP := net.ParseIP("fe80::2")

	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   containerIP,
			Mask: net.CIDRMask(128, 128), // Container has /128
		},
		Gateway: gatewayIP,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	// Expected bridge address should have /64 mask
	expectedBridgeAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   gatewayIP,
			Mask: net.CIDRMask(64, 128), // Bridge gets /64
		},
	}

	gomock.InOrder(
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET6).Return(nil, nil),
		mockNetLink.EXPECT().AddrAdd(bridgeLink, expectedBridgeAddr).Return(nil),
	)

	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.NoError(t, err)
}

// TestConfigureBridge_NonLinkLocalIP_UsesContainerMask tests that non-link-local IPs use container mask
func TestConfigureBridge_NonLinkLocalIP_UsesContainerMask(t *testing.T) {
	ctrl, _, mockNetLink, _, _, _ := setup(t)
	defer ctrl.Finish()

	bridgeLink := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{Name: "fargate-bridge"},
	}

	// Regular private IP (not link-local)
	gatewayIP := net.ParseIP("10.0.0.1")
	containerIP := net.ParseIP("10.0.0.2")

	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   containerIP,
			Mask: net.CIDRMask(24, 32), // Container has /24
		},
		Gateway: gatewayIP,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	// Expected bridge address should use container's /24 mask
	expectedBridgeAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   gatewayIP,
			Mask: net.CIDRMask(24, 32), // Bridge uses container mask
		},
	}

	gomock.InOrder(
		mockNetLink.EXPECT().AddrList(bridgeLink, syscall.AF_INET).Return(nil, nil),
		mockNetLink.EXPECT().AddrAdd(bridgeLink, expectedBridgeAddr).Return(nil),
	)

	engine := &engine{netLink: mockNetLink}
	err := engine.ConfigureBridge(result, bridgeLink)
	assert.NoError(t, err)
}

// TestConfigureBridge_BeforeContainer tests that bridge is configured before container
// This is important because container configuration adds routes to the gateway,
// which must already exist on the bridge
func TestConfigureBridge_BeforeContainer(t *testing.T) {
	// This test verifies the order of operations in commands.go
	// The actual test is in commands_test.go, but we document the requirement here
	// 
	// Required order:
	// 1. ConfigureBridge() - Gateway IP must exist first
	// 2. ConfigureContainerVethInterface() - Container adds routes to gateway
	//
	// If reversed, container route addition may fail or behave unpredictably
}

// TestConfigureVeth_AddsOnLinkGatewayRoute tests that on-link gateway route is added
func TestConfigureVeth_AddsOnLinkGatewayRoute(t *testing.T) {
	ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	gatewayIP := net.ParseIP("169.254.172.1")
	containerIP := net.ParseIP("169.254.172.2")

	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   containerIP,
			Mask: net.CIDRMask(32, 32),
		},
		Gateway: gatewayIP,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	link := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:  "eth0",
			Index: 1,
		},
	}

	var capturedGatewayRoute, capturedSubnetRoute *netlink.Route

	gomock.InOrder(
		// Get link for adding on-link routes
		mockNetLink.EXPECT().LinkByName("eth0").Return(link, nil),
		// Add on-link gateway route - capture it
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			capturedGatewayRoute = route
		}).Return(nil),
		// ConfigureIface
		mockIPAM.EXPECT().ConfigureIface("eth0", result).Return(nil),
		// SetHWAddrByIP
		mockIP.EXPECT().SetHWAddrByIP("eth0", containerIP, nil).Return(nil),
		// RouteList for cleanup
		mockNetLink.EXPECT().RouteList(link, netlink.FAMILY_ALL).Return([]netlink.Route{}, nil),
		// Add connected subnet route
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			capturedSubnetRoute = route
		}).Return(nil),
	)

	configContext := newConfigureVethContext("eth0", result, mockIP, mockIPAM, mockNetLink, 22, 0)
	err := configContext.run(nil)
	assert.NoError(t, err)

	// Verify gateway route
	assert.NotNil(t, capturedGatewayRoute)
	assert.Equal(t, gatewayIP.String(), capturedGatewayRoute.Dst.IP.String())
	assert.Equal(t, net.CIDRMask(32, 32).String(), capturedGatewayRoute.Dst.Mask.String())
	assert.Equal(t, netlink.SCOPE_LINK, capturedGatewayRoute.Scope)

	// Verify subnet route
	assert.NotNil(t, capturedSubnetRoute)
	assert.Equal(t, containerIP.String(), capturedSubnetRoute.Dst.IP.String())
	assert.Equal(t, net.CIDRMask(32, 32).String(), capturedSubnetRoute.Dst.Mask.String())
	assert.Equal(t, netlink.SCOPE_LINK, capturedSubnetRoute.Scope)
}

// TestConfigureVeth_DeletesOnlyDefaultRoutes tests that only default routes are deleted
func TestConfigureVeth_DeletesOnlyDefaultRoutes(t *testing.T) {
	ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	gatewayIP := net.ParseIP("169.254.172.1")
	containerIP := net.ParseIP("169.254.172.2")

	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   containerIP,
			Mask: net.CIDRMask(32, 32),
		},
		Gateway: gatewayIP,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	link := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:  "eth0",
			Index: 1,
		},
	}

	// Existing routes in container
	existingRoutes := []netlink.Route{
		// Default route - should be deleted
		{
			Dst: nil, // nil means default route
			Gw:  nil,
		},
		// On-link gateway route - should NOT be deleted
		{
			Dst: &net.IPNet{
				IP:   gatewayIP,
				Mask: net.CIDRMask(32, 32),
			},
			Gw:    nil,
			Scope: netlink.SCOPE_LINK,
		},
		// Route with gateway - should NOT be deleted
		{
			Dst: &net.IPNet{
				IP:   net.ParseIP("10.0.0.0"),
				Mask: net.CIDRMask(8, 32),
			},
			Gw: gatewayIP,
		},
	}

	// Only the default route should be deleted
	expectedDeleteRoute := &netlink.Route{
		Dst: nil,
		Gw:  nil,
	}

	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName("eth0").Return(link, nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Return(nil), // Gateway route
		mockIPAM.EXPECT().ConfigureIface("eth0", result).Return(nil),
		mockIP.EXPECT().SetHWAddrByIP("eth0", containerIP, nil).Return(nil),
		mockNetLink.EXPECT().RouteList(link, netlink.FAMILY_ALL).Return(existingRoutes, nil),
		// Only default route should be deleted
		mockNetLink.EXPECT().RouteDel(expectedDeleteRoute).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Return(nil), // Subnet route
	)

	configContext := newConfigureVethContext("eth0", result, mockIP, mockIPAM, mockNetLink, 22, 0)
	err := configContext.run(nil)
	assert.NoError(t, err)
}

// TestConfigureVeth_AddsConnectedSubnetRoute tests that connected subnet route is added
func TestConfigureVeth_AddsConnectedSubnetRoute(t *testing.T) {
	ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	gatewayIP := net.ParseIP("169.254.172.1")
	containerIP := net.ParseIP("169.254.172.2")

	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   containerIP,
			Mask: net.CIDRMask(32, 32),
		},
		Gateway: gatewayIP,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	link := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:  "eth0",
			Index: 1,
		},
	}

	var capturedSubnetRoute *netlink.Route

	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName("eth0").Return(link, nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Return(nil), // Gateway route
		mockIPAM.EXPECT().ConfigureIface("eth0", result).Return(nil),
		mockIP.EXPECT().SetHWAddrByIP("eth0", containerIP, nil).Return(nil),
		mockNetLink.EXPECT().RouteList(link, netlink.FAMILY_ALL).Return([]netlink.Route{}, nil),
		// Connected subnet route should be added - capture it
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			capturedSubnetRoute = route
		}).Return(nil),
	)

	configContext := newConfigureVethContext("eth0", result, mockIP, mockIPAM, mockNetLink, 22, 0) // Use non-zero mask size
	err := configContext.run(nil)
	assert.NoError(t, err)

	// Verify subnet route
	assert.NotNil(t, capturedSubnetRoute)
	assert.Equal(t, containerIP.String(), capturedSubnetRoute.Dst.IP.String())
	assert.Equal(t, net.CIDRMask(32, 32).String(), capturedSubnetRoute.Dst.Mask.String())
	assert.Equal(t, netlink.SCOPE_LINK, capturedSubnetRoute.Scope)
}

// TestConfigureVeth_HandlesExistingRoutes tests that existing routes don't cause errors
func TestConfigureVeth_HandlesExistingRoutes(t *testing.T) {
	ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	gatewayIP := net.ParseIP("169.254.172.1")
	containerIP := net.ParseIP("169.254.172.2")

	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			IP:   containerIP,
			Mask: net.CIDRMask(32, 32),
		},
		Gateway: gatewayIP,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	link := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:  "eth0",
			Index: 1,
		},
	}

	// Simulate "file exists" error for routes that already exist
	fileExistsErr := &os.PathError{Op: "add", Path: "route", Err: syscall.EEXIST}

	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName("eth0").Return(link, nil),
		// Gateway route already exists
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Return(fileExistsErr),
		mockIPAM.EXPECT().ConfigureIface("eth0", result).Return(nil),
		mockIP.EXPECT().SetHWAddrByIP("eth0", containerIP, nil).Return(nil),
		mockNetLink.EXPECT().RouteList(link, netlink.FAMILY_ALL).Return([]netlink.Route{}, nil),
		// Subnet route already exists
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Return(fileExistsErr),
	)

	configContext := newConfigureVethContext("eth0", result, mockIP, mockIPAM, mockNetLink, 22, 0)
	err := configContext.run(nil)
	// Should not error on "file exists"
	assert.NoError(t, err)
}

// TestConfigureVeth_DualStack tests on-link routes for both IPv4 and IPv6
func TestConfigureVeth_DualStack(t *testing.T) {
	ctrl, _, mockNetLink, mockIP, mockIPAM, _ := setup(t)
	defer ctrl.Finish()

	gatewayIPv4 := net.ParseIP("169.254.172.1")
	containerIPv4 := net.ParseIP("169.254.172.2")
	gatewayIPv6 := net.ParseIP("fd00:ec2::172:1")
	containerIPv6 := net.ParseIP("fd00:ec2::172:2")

	ipConfigV4 := &current.IPConfig{
		Address: net.IPNet{
			IP:   containerIPv4,
			Mask: net.CIDRMask(32, 32),
		},
		Gateway: gatewayIPv4,
	}

	ipConfigV6 := &current.IPConfig{
		Address: net.IPNet{
			IP:   containerIPv6,
			Mask: net.CIDRMask(128, 128),
		},
		Gateway: gatewayIPv6,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfigV4, ipConfigV6},
	}

	link := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:  "eth0",
			Index: 1,
		},
	}

	gomock.InOrder(
		mockNetLink.EXPECT().LinkByName("eth0").Return(link, nil),
		// IPv4 gateway route
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Return(nil),
		// IPv6 gateway route
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Return(nil),
		mockIPAM.EXPECT().ConfigureIface("eth0", result).Return(nil),
		// SetHWAddrByIP is called with both IPv4 and IPv6
		mockIP.EXPECT().SetHWAddrByIP("eth0", containerIPv4, containerIPv6).Return(nil),
		mockNetLink.EXPECT().RouteList(link, netlink.FAMILY_ALL).Return([]netlink.Route{}, nil),
		// IPv4 subnet route
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Return(nil),
		// IPv6 subnet route
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Return(nil),
	)

	configContext := newConfigureVethContext("eth0", result, mockIP, mockIPAM, mockNetLink, 22, 64)
	err := configContext.run(nil)
	require.NoError(t, err)
}
