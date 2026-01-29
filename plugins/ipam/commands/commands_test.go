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
	"net"
	"testing"
	"testing/quick"

	"github.com/aws/amazon-ecs-cni-plugins/plugins/ipam/config"
	"github.com/aws/amazon-ecs-cni-plugins/plugins/ipam/ipstore"
	mock_ipstore "github.com/aws/amazon-ecs-cni-plugins/plugins/ipam/ipstore/mocks"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setup(subnetStr, ipStr, gwStr string, t *testing.T) (*config.IPAMConfig, *mock_ipstore.MockIPAllocator) {
	var (
		ip     net.IPNet
		gw     net.IP
		subnet *net.IPNet
		err    error
	)

	_, subnet, err = net.ParseCIDR(subnetStr)
	require.NoError(t, err, "parsing the subnet string failed")

	if ipStr != "" {
		tip, tsub, err := net.ParseCIDR(ipStr)
		require.NoError(t, err, "parsing the ip address failed")
		ip = net.IPNet{
			IP:   tip,
			Mask: tsub.Mask,
		}
	}
	if gwStr != "" {
		gw = net.ParseIP(gwStr)
	}

	ipamConf := &config.IPAMConfig{
		Type:        "ipam",
		IPV4Subnet:  types.IPNet{IP: subnet.IP, Mask: subnet.Mask},
		IPV4Address: types.IPNet{IP: ip.IP, Mask: ip.Mask},
		IPV4Gateway: gw,
	}

	mockCtrl := gomock.NewController(t)
	allocator := mock_ipstore.NewMockIPAllocator(mockCtrl)

	return ipamConf, allocator
}

// TestGetSpecificIPV4HappyPath tests the specified ip will be assigned
func TestGetSpecificIPV4HappyPath(t *testing.T) {
	conf, allocator := setup("10.0.0.0/29", "10.0.0.3/29", "", t)

	gomock.InOrder(
		allocator.EXPECT().Assign(gomock.Any(), gomock.Any()).Return(nil),
	)

	assignedAddress, err := getIPV4Address(allocator, conf)
	assert.NoError(t, err, "get specific ip from subnet failed")
	assert.Equal(t, "10.0.0.3/29", assignedAddress.String(), "Assigned IP is not the one specified")
}

// TestGetNextIPV4HappyPath tests if ip isn't specified, next available one will be picked up
func TestGetNextIPV4HappyPath(t *testing.T) {
	conf, allocator := setup("10.0.0.0/29", "", "", t)

	gomock.InOrder(
		allocator.EXPECT().Exists(config.LastKnownIPKey).Return(true, nil),
		allocator.EXPECT().Get(config.LastKnownIPKey).Return("10.0.0.3", nil),
		allocator.EXPECT().SetLastKnownIP(net.ParseIP("10.0.0.3")),
		allocator.EXPECT().GetAvailableIP(gomock.Any()).Return("10.0.0.4", nil),
	)

	assignedAddress, err := getIPV4Address(allocator, conf)
	assert.NoError(t, err, "get available ip from subnet failed")
	assert.Equal(t, "10.0.0.4/29", assignedAddress.String(), "Assigned ip should be the next available ip")
}

// TestGetUsedIPv4 tests if the specified ip has already been used, it will cause error
func TestGetUsedIPv4(t *testing.T) {
	conf, allocator := setup("10.0.0.0/29", "10.0.0.3/29", "", t)

	allocator.EXPECT().Assign(gomock.Any(), gomock.Any()).Return(errors.New("IP has already been used"))

	assignedAddress, err := getIPV4Address(allocator, conf)
	assert.Error(t, err, "assign an used ip should cause error")
	assert.Nil(t, assignedAddress, "error will cause ip not be assigned")
}

// TestIPUsedUPInSubnet tests there is no available ip in the subnet should cause error
func TestIPUsedUPInSubnet(t *testing.T) {
	conf, allocator := setup("10.0.0.0/29", "", "", t)

	gomock.InOrder(
		allocator.EXPECT().Exists(config.LastKnownIPKey).Return(true, nil),
		allocator.EXPECT().Get(config.LastKnownIPKey).Return("10.0.0.3", nil),
		allocator.EXPECT().SetLastKnownIP(net.ParseIP("10.0.0.3")),
		allocator.EXPECT().GetAvailableIP(gomock.Any()).Return("", errors.New("no available ip in the subnet")),
	)

	assignedAddress, err := getIPV4Address(allocator, conf)
	assert.Error(t, err, "no available ip in the subnet should cause error")
	assert.Nil(t, assignedAddress, "error will cause ip not be assigned")
}

// TestGWUsed tests the default gateway can be used by multiple container
func TestGWUsed(t *testing.T) {
	_, allocator := setup("10.0.0.0/29", "", "", t)
	gw := "10.0.0.1"

	gomock.InOrder(
		allocator.EXPECT().Get(gw).Return(config.GatewayValue, nil),
	)

	err := verifyGateway(net.ParseIP("10.0.0.1"), allocator)
	assert.NoError(t, err, "gateway can be used by multiple containers")
}

// TestGWUsedByContainer tests the gateway address used by container should cause error
func TestGWUsedByContainer(t *testing.T) {
	_, allocator := setup("10.0.0.0/29", "", "10.0.0.2/29", t)

	gomock.InOrder(
		allocator.EXPECT().Get("10.0.0.2").Return("not gateway", nil),
	)

	err := verifyGateway(net.ParseIP("10.0.0.2"), allocator)
	assert.Error(t, err, "gateway used by container should fail the command")
}

func TestConstructResult(t *testing.T) {
	conf, _ := setup("10.0.0.0/29", "", "", t)

	tip, tsub, err := net.ParseCIDR("10.0.0.1/29")
	assert.NoError(t, err, "Parsing the cidr failed")
	ip := net.IPNet{
		IP:   tip,
		Mask: tsub.Mask,
	}

	result, err := constructResults(conf, &ip, nil)
	assert.NoError(t, err)
	assert.NotNil(t, result, "Construct result for bridge plugin failed")
	assert.Equal(t, 1, len(result.IPs), "Only one ip should be assigned each time")
}

func TestConstructResultErrorForIPV6(t *testing.T) {
	conf, _ := setup("10.0.0.0/29", "", "", t)

	tip, tsub, err := net.ParseCIDR("2001:db8::2:1/60")
	assert.NoError(t, err, "Parsing the cidr failed")
	ip := net.IPNet{
		IP:   tip,
		Mask: tsub.Mask,
	}

	// When passing an IPv6 address as the IPv4 parameter, it should error
	_, err = constructResults(conf, &ip, nil)
	assert.Error(t, err, "passing ipv6 as ipv4 should cause error")
}

func TestAddExistedIP(t *testing.T) {
	conf, allocator := setup("10.0.0.0/29", "10.0.0.3/29", "10.0.0.1", t)

	gomock.InOrder(
		allocator.EXPECT().Get(conf.IPV4Gateway.String()).Return(config.GatewayValue, nil),
		allocator.EXPECT().Assign(conf.IPV4Address.IP.String(), gomock.Any()).Return(errors.New("ip already been used")),
	)

	err := add(allocator, conf, "0.3.0")
	assert.Error(t, err, "assign used ip should cause ADD fail")
}

func TestAddConstructResultError(t *testing.T) {
	conf, allocator := setup("10.0.0.0/29", "2001:db8::2:1/60", "10.0.0.1", t)

	gomock.InOrder(
		allocator.EXPECT().Get(conf.IPV4Gateway.String()).Return(config.GatewayValue, nil),
		allocator.EXPECT().Assign(conf.IPV4Address.IP.String(), gomock.Any()).Return(nil),
		allocator.EXPECT().Update(config.LastKnownIPKey, conf.IPV4Address.IP.String()).Return(nil),
	)
	err := add(allocator, conf, "0.3.0")
	assert.Error(t, err, "assign used ip should cause ADD fail")
}

// TestPrintResultError tests the types.Print error cause command fail
func TestPrintResultError(t *testing.T) {
	conf, allocator := setup("10.0.0.0/29", "10.0.0.2/29", "10.0.0.1", t)

	gomock.InOrder(
		allocator.EXPECT().Get(conf.IPV4Gateway.String()).Return(config.GatewayValue, nil),
		allocator.EXPECT().Assign(conf.IPV4Address.IP.String(), gomock.Any()).Return(nil),
		allocator.EXPECT().Update(config.LastKnownIPKey, conf.IPV4Address.IP.String()).Return(nil),
	)
	err := add(allocator, conf, "invalid")
	assert.Error(t, err, "invalid cni version should cause ADD fail")
}

func TestUpdateFail(t *testing.T) {
	conf, allocator := setup("10.0.0.0/29", "10.0.0.2/29", "", t)

	gomock.InOrder(
		allocator.EXPECT().Release("10.0.0.2").Return(nil),
		allocator.EXPECT().Update(config.LastKnownIPKey, conf.IPV4Address.IP.String()).Return(errors.New("update fail")),
	)

	err := del(allocator, conf)
	assert.NoError(t, err, "Update the last known IP should not cause the DEL fail")
}

func TestDelReleaseError(t *testing.T) {
	conf, allocator := setup("10.0.0.0/29", "10.0.0.2/29", "", t)

	gomock.InOrder(
		allocator.EXPECT().Release("10.0.0.2").Return(errors.New("failed to query the db")),
	)

	err := del(allocator, conf)
	assert.Error(t, err, "Release the ip from db failed should cause the DEL fail")
}

// TestDelByID tests the ipam plugin release ip by id
func TestDelByID(t *testing.T) {
	conf, allocator := setup("10.0.0.0/29", "10.0.0.2/29", "", t)
	conf.ID = "TestDelByID"
	conf.IPV4Address = types.IPNet{}

	gomock.InOrder(
		allocator.EXPECT().ReleaseByID(conf.ID).Return("10.0.0.3", "", nil),
		allocator.EXPECT().Update(config.LastKnownIPKey, "10.0.0.3").Return(nil),
	)

	err := del(allocator, conf)
	assert.NoError(t, err)
}

func TestDelWithoutIDAndIP(t *testing.T) {
	conf, _ := setup("10.0.0.0/29", "10.0.0.2/29", "", t)
	conf.IPV4Address = types.IPNet{}

	err := validateDelConfiguration(conf)
	assert.Error(t, err, "Empty ip and id should cause deletion fail")
}

// setupIPv6 creates an IPv6-only configuration for testing
func setupIPv6(subnetStr, ipStr, gwStr string, t *testing.T) (*config.IPAMConfig, *mock_ipstore.MockIPAllocator) {
	var (
		ip     net.IPNet
		gw     net.IP
		subnet *net.IPNet
		err    error
	)

	_, subnet, err = net.ParseCIDR(subnetStr)
	require.NoError(t, err, "parsing the IPv6 subnet string failed")

	if ipStr != "" {
		tip, tsub, err := net.ParseCIDR(ipStr)
		require.NoError(t, err, "parsing the IPv6 address failed")
		ip = net.IPNet{
			IP:   tip,
			Mask: tsub.Mask,
		}
	}
	if gwStr != "" {
		gw = net.ParseIP(gwStr)
	}

	ipamConf := &config.IPAMConfig{
		Type:        "ipam",
		IPV6Subnet:  types.IPNet{IP: subnet.IP, Mask: subnet.Mask},
		IPV6Address: types.IPNet{IP: ip.IP, Mask: ip.Mask},
		IPV6Gateway: gw,
	}

	mockCtrl := gomock.NewController(t)
	allocator := mock_ipstore.NewMockIPAllocator(mockCtrl)

	return ipamConf, allocator
}

// setupDualStack creates a dual-stack configuration for testing
func setupDualStack(v4SubnetStr, v4IPStr, v4GWStr, v6SubnetStr, v6IPStr, v6GWStr string, t *testing.T) (*config.IPAMConfig, *mock_ipstore.MockIPAllocator) {
	var (
		ipv4     net.IPNet
		ipv6     net.IPNet
		gwv4     net.IP
		gwv6     net.IP
		subnetv4 *net.IPNet
		subnetv6 *net.IPNet
		err      error
	)

	_, subnetv4, err = net.ParseCIDR(v4SubnetStr)
	require.NoError(t, err, "parsing the IPv4 subnet string failed")

	_, subnetv6, err = net.ParseCIDR(v6SubnetStr)
	require.NoError(t, err, "parsing the IPv6 subnet string failed")

	if v4IPStr != "" {
		tip, tsub, err := net.ParseCIDR(v4IPStr)
		require.NoError(t, err, "parsing the IPv4 address failed")
		ipv4 = net.IPNet{IP: tip, Mask: tsub.Mask}
	}
	if v6IPStr != "" {
		tip, tsub, err := net.ParseCIDR(v6IPStr)
		require.NoError(t, err, "parsing the IPv6 address failed")
		ipv6 = net.IPNet{IP: tip, Mask: tsub.Mask}
	}
	if v4GWStr != "" {
		gwv4 = net.ParseIP(v4GWStr)
	}
	if v6GWStr != "" {
		gwv6 = net.ParseIP(v6GWStr)
	}

	ipamConf := &config.IPAMConfig{
		Type:        "ipam",
		IPV4Subnet:  types.IPNet{IP: subnetv4.IP, Mask: subnetv4.Mask},
		IPV4Address: types.IPNet{IP: ipv4.IP, Mask: ipv4.Mask},
		IPV4Gateway: gwv4,
		IPV6Subnet:  types.IPNet{IP: subnetv6.IP, Mask: subnetv6.Mask},
		IPV6Address: types.IPNet{IP: ipv6.IP, Mask: ipv6.Mask},
		IPV6Gateway: gwv6,
	}

	mockCtrl := gomock.NewController(t)
	allocator := mock_ipstore.NewMockIPAllocator(mockCtrl)

	return ipamConf, allocator
}

// TestGetSpecificIPV6HappyPath tests the specified IPv6 ip will be assigned
func TestGetSpecificIPV6HappyPath(t *testing.T) {
	conf, allocator := setupIPv6("2001:db8::/64", "2001:db8::3/64", "", t)

	gomock.InOrder(
		allocator.EXPECT().Assign(ipstore.IPPrefixV6+conf.IPV6Address.IP.String(), gomock.Any()).Return(nil),
	)

	assignedAddress, err := getIPV6Address(allocator, conf)
	assert.NoError(t, err, "get specific IPv6 ip from subnet failed")
	assert.Equal(t, "2001:db8::3/64", assignedAddress.String(), "Assigned IPv6 IP is not the one specified")
}

// TestGetNextIPV6HappyPath tests if IPv6 ip isn't specified, next available one will be picked up
func TestGetNextIPV6HappyPath(t *testing.T) {
	conf, allocator := setupIPv6("2001:db8::/64", "", "", t)

	gomock.InOrder(
		allocator.EXPECT().Exists(ipstore.LastKnownIPv6Key).Return(true, nil),
		allocator.EXPECT().Get(ipstore.LastKnownIPv6Key).Return("2001:db8::3", nil),
		allocator.EXPECT().SetLastKnownIPv6(net.ParseIP("2001:db8::3")),
		allocator.EXPECT().GetAvailableIPv6(gomock.Any()).Return("2001:db8::4", nil),
	)

	assignedAddress, err := getIPV6Address(allocator, conf)
	assert.NoError(t, err, "get available IPv6 ip from subnet failed")
	assert.Equal(t, "2001:db8::4/64", assignedAddress.String(), "Assigned IPv6 ip should be the next available ip")
}

// TestGetUsedIPv6 tests if the specified IPv6 ip has already been used, it will cause error
func TestGetUsedIPv6(t *testing.T) {
	conf, allocator := setupIPv6("2001:db8::/64", "2001:db8::3/64", "", t)

	allocator.EXPECT().Assign(ipstore.IPPrefixV6+conf.IPV6Address.IP.String(), gomock.Any()).Return(errors.New("IP has already been used"))

	assignedAddress, err := getIPV6Address(allocator, conf)
	assert.Error(t, err, "assign a used IPv6 ip should cause error")
	assert.Nil(t, assignedAddress, "error will cause IPv6 ip not be assigned")
}

// TestAddIPv6OnlyHappyPath tests ADD command with IPv6-only configuration
func TestAddIPv6OnlyHappyPath(t *testing.T) {
	conf, allocator := setupIPv6("2001:db8::/64", "2001:db8::2/64", "2001:db8::1", t)

	gomock.InOrder(
		allocator.EXPECT().Get(ipstore.IPPrefixV6+conf.IPV6Gateway.String()).Return(config.GatewayV6Value, nil),
		allocator.EXPECT().Assign(ipstore.IPPrefixV6+conf.IPV6Address.IP.String(), gomock.Any()).Return(nil),
		allocator.EXPECT().Update(ipstore.LastKnownIPv6Key, conf.IPV6Address.IP.String()).Return(nil),
	)

	err := add(allocator, conf, "0.3.0")
	assert.NoError(t, err, "ADD with IPv6-only config should succeed")
}

// TestAddDualStackHappyPath tests ADD command with dual-stack configuration
func TestAddDualStackHappyPath(t *testing.T) {
	conf, allocator := setupDualStack(
		"10.0.0.0/24", "10.0.0.2/24", "10.0.0.1",
		"2001:db8::/64", "2001:db8::2/64", "2001:db8::1", t)

	gomock.InOrder(
		// IPv4 handling
		allocator.EXPECT().Get(conf.IPV4Gateway.String()).Return(config.GatewayValue, nil),
		allocator.EXPECT().Assign(conf.IPV4Address.IP.String(), gomock.Any()).Return(nil),
		allocator.EXPECT().Update(config.LastKnownIPKey, conf.IPV4Address.IP.String()).Return(nil),
		// IPv6 handling
		allocator.EXPECT().Get(ipstore.IPPrefixV6+conf.IPV6Gateway.String()).Return(config.GatewayV6Value, nil),
		allocator.EXPECT().Assign(ipstore.IPPrefixV6+conf.IPV6Address.IP.String(), gomock.Any()).Return(nil),
		allocator.EXPECT().Update(ipstore.LastKnownIPv6Key, conf.IPV6Address.IP.String()).Return(nil),
	)

	err := add(allocator, conf, "0.3.0")
	assert.NoError(t, err, "ADD with dual-stack config should succeed")
}

// TestDelIPv6Address tests DEL command with IPv6 address
func TestDelIPv6Address(t *testing.T) {
	conf, allocator := setupIPv6("2001:db8::/64", "2001:db8::2/64", "", t)

	gomock.InOrder(
		allocator.EXPECT().Release(ipstore.IPPrefixV6+conf.IPV6Address.IP.String()).Return(nil),
		allocator.EXPECT().Update(ipstore.LastKnownIPv6Key, conf.IPV6Address.IP.String()).Return(nil),
	)

	err := del(allocator, conf)
	assert.NoError(t, err, "DEL with IPv6 address should succeed")
}

// TestDelByIDDualStack tests the ipam plugin release both IPv4 and IPv6 by id
func TestDelByIDDualStack(t *testing.T) {
	conf, allocator := setupDualStack(
		"10.0.0.0/24", "", "",
		"2001:db8::/64", "", "", t)
	conf.ID = "TestDelByIDDualStack"

	gomock.InOrder(
		allocator.EXPECT().ReleaseByID(conf.ID).Return("10.0.0.3", "2001:db8::3", nil),
		allocator.EXPECT().Update(config.LastKnownIPKey, "10.0.0.3").Return(nil),
		allocator.EXPECT().Update(ipstore.LastKnownIPv6Key, "2001:db8::3").Return(nil),
	)

	err := del(allocator, conf)
	assert.NoError(t, err, "DEL by ID in dual-stack mode should succeed")
}

// TestConstructResultIPv6Only tests constructResults with IPv6-only configuration
func TestConstructResultIPv6Only(t *testing.T) {
	conf, _ := setupIPv6("2001:db8::/64", "", "2001:db8::1", t)

	tip, tsub, err := net.ParseCIDR("2001:db8::2/64")
	assert.NoError(t, err, "Parsing the IPv6 cidr failed")
	ip := net.IPNet{
		IP:   tip,
		Mask: tsub.Mask,
	}

	result, err := constructResults(conf, nil, &ip)
	assert.NoError(t, err)
	assert.NotNil(t, result, "Construct result for IPv6-only config failed")
	assert.Equal(t, 1, len(result.IPs), "Only one IP should be assigned for IPv6-only")
	assert.Equal(t, "6", result.IPs[0].Version, "IP version should be 6")
}

// TestConstructResultDualStack tests constructResults with dual-stack configuration
func TestConstructResultDualStack(t *testing.T) {
	conf, _ := setupDualStack(
		"10.0.0.0/24", "", "10.0.0.1",
		"2001:db8::/64", "", "2001:db8::1", t)

	tipv4, tsubv4, err := net.ParseCIDR("10.0.0.2/24")
	assert.NoError(t, err, "Parsing the IPv4 cidr failed")
	ipv4 := net.IPNet{IP: tipv4, Mask: tsubv4.Mask}

	tipv6, tsubv6, err := net.ParseCIDR("2001:db8::2/64")
	assert.NoError(t, err, "Parsing the IPv6 cidr failed")
	ipv6 := net.IPNet{IP: tipv6, Mask: tsubv6.Mask}

	result, err := constructResults(conf, &ipv4, &ipv6)
	assert.NoError(t, err)
	assert.NotNil(t, result, "Construct result for dual-stack config failed")
	assert.Equal(t, 2, len(result.IPs), "Two IPs should be assigned for dual-stack")
	assert.Equal(t, "4", result.IPs[0].Version, "First IP version should be 4")
	assert.Equal(t, "6", result.IPs[1].Version, "Second IP version should be 6")
}

// TestConstructResultErrorForIPV4AsIPv6 tests passing IPv4 as IPv6 causes error
func TestConstructResultErrorForIPV4AsIPv6(t *testing.T) {
	conf, _ := setupIPv6("2001:db8::/64", "", "", t)

	tip, tsub, err := net.ParseCIDR("10.0.0.2/24")
	assert.NoError(t, err, "Parsing the cidr failed")
	ip := net.IPNet{
		IP:   tip,
		Mask: tsub.Mask,
	}

	// When passing an IPv4 address as the IPv6 parameter, it should error
	_, err = constructResults(conf, nil, &ip)
	assert.Error(t, err, "passing ipv4 as ipv6 should cause error")
}

// TestValidateDelConfigurationWithIPv6 tests validateDelConfiguration accepts IPv6 address
func TestValidateDelConfigurationWithIPv6(t *testing.T) {
	conf, _ := setupIPv6("2001:db8::/64", "2001:db8::2/64", "", t)

	err := validateDelConfiguration(conf)
	assert.NoError(t, err, "validateDelConfiguration should accept IPv6 address")
}

// TestVerifyGatewayV6Used tests the IPv6 gateway can be used by multiple containers
func TestVerifyGatewayV6Used(t *testing.T) {
	_, allocator := setupIPv6("2001:db8::/64", "", "", t)
	gw := "2001:db8::1"

	gomock.InOrder(
		allocator.EXPECT().Get(ipstore.IPPrefixV6+gw).Return(config.GatewayV6Value, nil),
	)

	err := verifyGatewayV6(net.ParseIP(gw), allocator)
	assert.NoError(t, err, "IPv6 gateway can be used by multiple containers")
}

// TestVerifyGatewayV6UsedByContainer tests the IPv6 gateway address used by container should cause error
func TestVerifyGatewayV6UsedByContainer(t *testing.T) {
	_, allocator := setupIPv6("2001:db8::/64", "", "2001:db8::2", t)

	gomock.InOrder(
		allocator.EXPECT().Get(ipstore.IPPrefixV6+"2001:db8::2").Return("not gateway", nil),
	)

	err := verifyGatewayV6(net.ParseIP("2001:db8::2"), allocator)
	assert.Error(t, err, "IPv6 gateway used by container should fail the command")
}

// TestConstructResultNoIPs tests constructResults with no IPs returns error
func TestConstructResultNoIPs(t *testing.T) {
	conf, _ := setup("10.0.0.0/29", "", "", t)

	result, err := constructResults(conf, nil, nil)
	assert.Error(t, err, "constructResults with no IPs should return error")
	assert.Nil(t, result, "result should be nil when no IPs configured")
}

// =============================================================================
// Property-Based Tests
// =============================================================================

// Feature: ipv6-support, Property 3: IPv4-Only Mode Operation
// For any configuration containing only ipv4-subnet (no ipv6-subnet), the ADD command
// shall return a CNI result containing exactly one IP configuration with version "4".
// **Validates: Requirements 2.1**
func TestProperty_IPv4OnlyModeOperation(t *testing.T) {
	f := func(lastOctet uint8) bool {
		// Constrain to valid host addresses (1-254)
		if lastOctet == 0 || lastOctet == 255 {
			return true // Skip invalid inputs
		}

		// Create IPv4-only config
		_, subnet, _ := net.ParseCIDR("10.0.0.0/24")
		ipStr := net.IPv4(10, 0, 0, lastOctet).String()
		ip := net.ParseIP(ipStr)

		conf := &config.IPAMConfig{
			Type:        "ipam",
			IPV4Subnet:  types.IPNet{IP: subnet.IP, Mask: subnet.Mask},
			IPV4Address: types.IPNet{IP: ip, Mask: subnet.Mask},
			IPV4Gateway: net.ParseIP("10.0.0.1"),
		}

		// Create IPv4 result directly (simulating successful allocation)
		ipv4Result := &net.IPNet{
			IP:   ip,
			Mask: subnet.Mask,
		}

		// Construct result - this is the core property we're testing
		result, err := constructResults(conf, ipv4Result, nil)
		if err != nil {
			return false
		}

		// Verify: exactly one IP with version "4"
		return len(result.IPs) == 1 && result.IPs[0].Version == "4"
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 100}); err != nil {
		t.Error(err)
	}
}

// Feature: ipv6-support, Property 4: IPv6-Only Mode Operation
// For any configuration containing only ipv6-subnet (no ipv4-subnet), the ADD command
// shall return a CNI result containing exactly one IP configuration with version "6".
// **Validates: Requirements 2.2**
func TestProperty_IPv6OnlyModeOperation(t *testing.T) {
	f := func(lastWord uint16) bool {
		// Constrain to valid host addresses (skip 0 which is network address)
		if lastWord == 0 {
			return true // Skip network address
		}

		// Create IPv6-only config
		_, subnet, _ := net.ParseCIDR("2001:db8::/64")
		// Create IPv6 address with the random last word
		ipv6Bytes := make([]byte, 16)
		copy(ipv6Bytes, subnet.IP.To16())
		ipv6Bytes[14] = byte(lastWord >> 8)
		ipv6Bytes[15] = byte(lastWord & 0xff)
		ip := net.IP(ipv6Bytes)

		conf := &config.IPAMConfig{
			Type:        "ipam",
			IPV6Subnet:  types.IPNet{IP: subnet.IP, Mask: subnet.Mask},
			IPV6Address: types.IPNet{IP: ip, Mask: subnet.Mask},
			IPV6Gateway: net.ParseIP("2001:db8::1"),
		}

		// Create IPv6 result directly (simulating successful allocation)
		ipv6Result := &net.IPNet{
			IP:   ip,
			Mask: subnet.Mask,
		}

		// Construct result - this is the core property we're testing
		result, err := constructResults(conf, nil, ipv6Result)
		if err != nil {
			return false
		}

		// Verify: exactly one IP with version "6"
		return len(result.IPs) == 1 && result.IPs[0].Version == "6"
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 100}); err != nil {
		t.Error(err)
	}
}

// Feature: ipv6-support, Property 5: Dual-Stack Mode Operation
// For any configuration containing both ipv4-subnet and ipv6-subnet, the ADD command
// shall return a CNI result containing exactly two IP configurations: one with version "4"
// and one with version "6".
// **Validates: Requirements 2.3**
func TestProperty_DualStackModeOperation(t *testing.T) {
	f := func(v4LastOctet uint8, v6LastWord uint16) bool {
		// Constrain to valid host addresses
		if v4LastOctet == 0 || v4LastOctet == 255 || v6LastWord == 0 {
			return true // Skip invalid inputs
		}

		// Create dual-stack config
		_, subnetV4, _ := net.ParseCIDR("10.0.0.0/24")
		_, subnetV6, _ := net.ParseCIDR("2001:db8::/64")

		ipv4 := net.IPv4(10, 0, 0, v4LastOctet)

		ipv6Bytes := make([]byte, 16)
		copy(ipv6Bytes, subnetV6.IP.To16())
		ipv6Bytes[14] = byte(v6LastWord >> 8)
		ipv6Bytes[15] = byte(v6LastWord & 0xff)
		ipv6 := net.IP(ipv6Bytes)

		conf := &config.IPAMConfig{
			Type:        "ipam",
			IPV4Subnet:  types.IPNet{IP: subnetV4.IP, Mask: subnetV4.Mask},
			IPV4Address: types.IPNet{IP: ipv4, Mask: subnetV4.Mask},
			IPV4Gateway: net.ParseIP("10.0.0.1"),
			IPV6Subnet:  types.IPNet{IP: subnetV6.IP, Mask: subnetV6.Mask},
			IPV6Address: types.IPNet{IP: ipv6, Mask: subnetV6.Mask},
			IPV6Gateway: net.ParseIP("2001:db8::1"),
		}

		// Create results directly (simulating successful allocation)
		ipv4Result := &net.IPNet{IP: ipv4, Mask: subnetV4.Mask}
		ipv6Result := &net.IPNet{IP: ipv6, Mask: subnetV6.Mask}

		// Construct result - this is the core property we're testing
		result, err := constructResults(conf, ipv4Result, ipv6Result)
		if err != nil {
			return false
		}

		// Verify: exactly two IPs, one v4 and one v6
		if len(result.IPs) != 2 {
			return false
		}
		hasV4 := false
		hasV6 := false
		for _, ipConfig := range result.IPs {
			if ipConfig.Version == "4" {
				hasV4 = true
			}
			if ipConfig.Version == "6" {
				hasV6 = true
			}
		}
		return hasV4 && hasV6
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 100}); err != nil {
		t.Error(err)
	}
}

// Feature: ipv6-support, Property 12: CNI Result Construction
// For any valid configuration, constructResults shall produce a CNI result where each IP
// configuration has the correct version field ("4" for IPv4, "6" for IPv6), and all
// configured routes are included.
// **Validates: Requirements 6.1, 6.2, 6.3, 6.4**
func TestProperty_CNIResultConstruction(t *testing.T) {
	f := func(hasIPv4, hasIPv6 bool, numV4Routes, numV6Routes uint8) bool {
		// At least one stack must be configured
		if !hasIPv4 && !hasIPv6 {
			return true // Skip invalid config
		}

		// Limit routes to reasonable number
		numV4Routes = numV4Routes % 5
		numV6Routes = numV6Routes % 5

		conf := &config.IPAMConfig{Type: "ipam"}

		var ipv4Result, ipv6Result *net.IPNet

		if hasIPv4 {
			_, subnetV4, _ := net.ParseCIDR("10.0.0.0/24")
			conf.IPV4Subnet = types.IPNet{IP: subnetV4.IP, Mask: subnetV4.Mask}
			conf.IPV4Gateway = net.ParseIP("10.0.0.1")

			// Add IPv4 routes
			for i := uint8(0); i < numV4Routes; i++ {
				_, dst, _ := net.ParseCIDR("192.168.0.0/24")
				conf.IPV4Routes = append(conf.IPV4Routes, &types.Route{Dst: *dst})
			}

			tip, tsub, _ := net.ParseCIDR("10.0.0.2/24")
			ipv4Result = &net.IPNet{IP: tip, Mask: tsub.Mask}
		}

		if hasIPv6 {
			_, subnetV6, _ := net.ParseCIDR("2001:db8::/64")
			conf.IPV6Subnet = types.IPNet{IP: subnetV6.IP, Mask: subnetV6.Mask}
			conf.IPV6Gateway = net.ParseIP("2001:db8::1")

			// Add IPv6 routes
			for i := uint8(0); i < numV6Routes; i++ {
				_, dst, _ := net.ParseCIDR("fd00::/64")
				conf.IPV6Routes = append(conf.IPV6Routes, &types.Route{Dst: *dst})
			}

			tip, tsub, _ := net.ParseCIDR("2001:db8::2/64")
			ipv6Result = &net.IPNet{IP: tip, Mask: tsub.Mask}
		}

		result, err := constructResults(conf, ipv4Result, ipv6Result)
		if err != nil {
			return false
		}

		// Verify IP count
		expectedIPCount := 0
		if hasIPv4 {
			expectedIPCount++
		}
		if hasIPv6 {
			expectedIPCount++
		}
		if len(result.IPs) != expectedIPCount {
			return false
		}

		// Verify version fields
		for _, ipConfig := range result.IPs {
			if ipConfig.Address.IP.To4() != nil {
				if ipConfig.Version != "4" {
					return false
				}
			} else {
				if ipConfig.Version != "6" {
					return false
				}
			}
		}

		// Verify routes count
		expectedRoutes := int(numV4Routes) + int(numV6Routes)
		if hasIPv4 {
			expectedRoutes = int(numV4Routes)
		} else {
			expectedRoutes = 0
		}
		if hasIPv6 {
			expectedRoutes += int(numV6Routes)
		}
		if len(result.Routes) != expectedRoutes {
			return false
		}

		return true
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 100}); err != nil {
		t.Error(err)
	}
}

// Feature: ipv6-support, Property 13: Backward Compatibility
// For any valid IPv4-only configuration (without any IPv6 fields), the plugin shall
// produce identical results to the current implementation.
// **Validates: Requirements 7.1, 7.2**
func TestProperty_BackwardCompatibility(t *testing.T) {
	f := func(lastOctet uint8, numRoutes uint8) bool {
		// Constrain to valid host addresses (1-254, excluding gateway at 1)
		if lastOctet == 0 || lastOctet == 1 || lastOctet == 255 {
			return true // Skip invalid inputs (network, gateway, broadcast)
		}

		// Limit routes to reasonable number
		numRoutes = numRoutes % 5

		// Create IPv4-only config WITHOUT any IPv6 fields
		// This simulates an existing IPv4-only configuration
		_, subnet, _ := net.ParseCIDR("10.0.0.0/24")
		ipStr := net.IPv4(10, 0, 0, lastOctet).String()
		ip := net.ParseIP(ipStr)
		gateway := net.ParseIP("10.0.0.1")

		conf := &config.IPAMConfig{
			Type:        "ipam",
			IPV4Subnet:  types.IPNet{IP: subnet.IP, Mask: subnet.Mask},
			IPV4Address: types.IPNet{IP: ip, Mask: subnet.Mask},
			IPV4Gateway: gateway,
			// IPv6 fields are intentionally NOT set (nil/empty)
			// This verifies backward compatibility - no new mandatory fields required
		}

		// Add IPv4 routes
		for i := uint8(0); i < numRoutes; i++ {
			_, dst, _ := net.ParseCIDR("192.168.0.0/24")
			conf.IPV4Routes = append(conf.IPV4Routes, &types.Route{Dst: *dst})
		}

		// Verify HasIPv4() returns true and HasIPv6() returns false
		// This confirms the config is recognized as IPv4-only
		if !conf.HasIPv4() {
			return false
		}
		if conf.HasIPv6() {
			return false
		}

		// Create IPv4 result (simulating successful allocation)
		ipv4Result := &net.IPNet{
			IP:   ip,
			Mask: subnet.Mask,
		}

		// Construct result with IPv4 only (nil for IPv6)
		// This is the core backward compatibility test
		result, err := constructResults(conf, ipv4Result, nil)
		if err != nil {
			return false
		}

		// Verify: exactly one IP with version "4"
		if len(result.IPs) != 1 {
			return false
		}
		if result.IPs[0].Version != "4" {
			return false
		}

		// Verify: the IP address is correctly set
		if !result.IPs[0].Address.IP.Equal(ip) {
			return false
		}

		// Verify: the gateway is correctly set
		if !result.IPs[0].Gateway.Equal(gateway) {
			return false
		}

		// Verify: routes are correctly included
		if len(result.Routes) != int(numRoutes) {
			return false
		}

		// Verify: the IP is a valid IPv4 address
		if result.IPs[0].Address.IP.To4() == nil {
			return false
		}

		return true
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 100}); err != nil {
		t.Error(err)
	}
}
