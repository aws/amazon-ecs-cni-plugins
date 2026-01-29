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

package config

import (
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultDBPath(t *testing.T) {
	os.Unsetenv(EnvDBPath)
	conf, err := LoadDBConfig()
	assert.NoError(t, err, "loading db config failed")
	assert.Equal(t, DefaultDBPath, conf.DB, "the default DB path will be used if not set by IPAM_DB_PATH")
}

func TestDBPathFromEnv(t *testing.T) {
	os.Setenv(EnvDBPath, "/tmp/test")
	defer os.Unsetenv(EnvDBPath)

	conf, err := LoadDBConfig()
	assert.NoError(t, err, "loading db config failed")
	assert.Equal(t, conf.DB, "/tmp/test")
}

// TestInvalidIPV4Address tests invalid IP address will cause error
func TestInvalidIPV4Address(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipv4-subnet": "10.0.0.0/24",
				"ipv4-address": "%s"
			}
		}`

	_, _, err := LoadIPAMConfig([]byte(fmt.Sprintf(conf, "10.0.0")), "")
	assert.Error(t, err, "expect error for invalid ip address")

	_, _, err = LoadIPAMConfig([]byte(fmt.Sprintf(conf, "10.0.0.1")), "")
	assert.Error(t, err, "expect error for missing mask in ipv4-address")

	_, _, err = LoadIPAMConfig([]byte(fmt.Sprintf(conf, "10.0.0.2/24")), "")
	assert.NoError(t, err, "valid ip address should not cause loading configuration error")

	_, _, err = LoadIPAMConfig([]byte(fmt.Sprintf(conf, "")), "")
	assert.Error(t, err, "expect error for missing IP address in the configuration")
}

// TestIPNotINSubnet tests if the specified ip is not in the subnet
func TestIPNotINSubnet(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipv4-gateway": "10.0.0.1",
				"ipv4-subnet": '10.0.0.0/24'
				"ipv4-address": "10.0.1.2/24"
			}
		}`

	_, _, err := LoadIPAMConfig([]byte(conf), "")
	assert.Error(t, err, "Specified IP not in the subnet should cause error")
}

// TestGatewayNotINSubnet tests if the specified ip is not in the subnet
func TestGatewayNotINSubnet(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipv4-gateway": "10.0.1.1",
				"ipv4-subnet": '10.0.0.0/24'
				"ipv4-address": "10.0.0.2/24"
			}
		}`

	_, _, err := LoadIPAMConfig([]byte(conf), "")
	assert.Error(t, err, "Specified gateway not in the subnet should cause error")
}

// TestIPIsNetworkAddress tests use network address should cause error
func TestIPIsNetworkAddress(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipv4-gateway": "10.0.0.1",
				"ipv4-subnet": "10.0.0.0/24",
				"ipv4-address": "10.0.0.0/24"
			}
		}`

	_, _, err := LoadIPAMConfig([]byte(conf), "")
	assert.Error(t, err, "Specified IP is the network address should cause error")
}

// TestIPIsBroadcastAddress tests use broadcast address should cause error
func TestIPIsBroadcastAddress(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipv4-gateway": "10.0.0.1",
				"ipv4-subnet": "10.0.0.0/24",
				"ipv4-address": "10.0.0.255/24"
			}
		}`

	_, _, err := LoadIPAMConfig([]byte(conf), "")
	assert.Error(t, err, "Specified IP is the broadcast address should cause error")
}

// TestGWIsNetworkAddress tests use network address should cause error
func TestGWIsNetworkAddress(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipv4-gateway": "10.0.0.0",
				"ipv4-subnet": "10.0.0.0/24",
				"ipv4-address": "10.0.0.2/24"
			}
		}`

	_, _, err := LoadIPAMConfig([]byte(conf), "")
	assert.Error(t, err, "Specified gateway is the broadcast address should cause error")
}

// TestGWIsBroadcastAddress tests use broadcast address should cause error
func TestGWIsBroadcastAddress(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipv4-gateway": "10.0.1.255",
				"ipv4-subnet": "10.0.0.0/24",
				"ipv4-address": "10.0.0.2/24"
			}
		}`

	_, _, err := LoadIPAMConfig([]byte(conf), "")
	assert.Error(t, err, "Specified gateway is the broadcast address should cause error")
}

// TestEmptySubnet tests missing subnet will cause error
func TestEmptySubnet(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipv4-gateway": "10.0.0.1",
				"ipv4-address": "10.0.0.2/24"
			}
		}`

	_, _, err := LoadIPAMConfig([]byte(conf), "")
	assert.Error(t, err, "expect error for missing subnet")
}

// TestDefaultGateway tests the default gateway will be given if gateway is not specified
func TestDefaultGateway(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipv4-address": "10.0.0.2/24",
				"ipv4-subnet": "10.0.0.0/24"
			}
		}`

	ipamConf, _, err := LoadIPAMConfig([]byte(conf), "")
	require.NoError(t, err, "valid configuration should not cause error")

	assert.Equal(t, ipamConf.IPV4Gateway.To4(), net.ParseIP("10.0.0.1").To4(), "expect to set the first address as default gateway")
}

func TestIPv4HappyPath(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipv4-address": "10.0.0.2/16",
				"ipv4-subnet": "10.0.0.0/16",
				"ipv4-gateway": "10.0.0.8",
				"ipv4-routes": [
				{"dst": "192.168.2.3/32"}
				]
			}
		}`

	ipamConf, _, err := LoadIPAMConfig([]byte(conf), "")
	require.NoError(t, err, "valid configuration should not cause error")

	assert.Equal(t, ipamConf.IPV4Gateway, net.ParseIP("10.0.0.8"), "result should be same as configured")
	assert.Equal(t, ipamConf.IPV4Address.IP, net.ParseIP("10.0.0.2"), "result should be same as configured")
	assert.Equal(t, ipamConf.IPV4Routes[0].Dst.String(), "192.168.2.3/32", "result should be same as configured")
}

func TestIsNetwokOrBroadcast(t *testing.T) {
	_, subnet, err := net.ParseCIDR("10.0.0.2/29")
	assert.NoError(t, err)

	result := isNetworkOrBroadcast(*subnet, net.ParseIP("10.0.0.0"))
	assert.True(t, result, "all 0 should be the network address of subnet")

	result = isNetworkOrBroadcast(*subnet, net.ParseIP("10.0.0.2"))
	assert.False(t, result, "regular ip is not broadcast or network address")

	result = isNetworkOrBroadcast(*subnet, net.ParseIP("10.0.0.7"))
	assert.True(t, result, "all 1 should be the broadcast address of subnet")
}

// TestIsIPv4 tests the isIPv4 helper function
func TestIsIPv4(t *testing.T) {
	testCases := []struct {
		name     string
		ip       net.IP
		expected bool
	}{
		{
			name:     "valid IPv4 address",
			ip:       net.ParseIP("10.0.0.1"),
			expected: true,
		},
		{
			name:     "valid IPv4 address 2",
			ip:       net.ParseIP("192.168.1.1"),
			expected: true,
		},
		{
			name:     "IPv6 address",
			ip:       net.ParseIP("2001:db8::1"),
			expected: false,
		},
		{
			name:     "IPv6 loopback",
			ip:       net.ParseIP("::1"),
			expected: false,
		},
		{
			name:     "nil IP",
			ip:       nil,
			expected: false,
		},
		{
			name:     "IPv4 loopback",
			ip:       net.ParseIP("127.0.0.1"),
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isIPv4(tc.ip)
			assert.Equal(t, tc.expected, result, "isIPv4(%v) should return %v", tc.ip, tc.expected)
		})
	}
}

// TestIsIPv6 tests the isIPv6 helper function
func TestIsIPv6(t *testing.T) {
	testCases := []struct {
		name     string
		ip       net.IP
		expected bool
	}{
		{
			name:     "valid IPv6 address",
			ip:       net.ParseIP("2001:db8::1"),
			expected: true,
		},
		{
			name:     "valid IPv6 full address",
			ip:       net.ParseIP("2001:0db8:0000:0000:0000:0000:0000:0001"),
			expected: true,
		},
		{
			name:     "IPv6 loopback",
			ip:       net.ParseIP("::1"),
			expected: true,
		},
		{
			name:     "IPv4 address",
			ip:       net.ParseIP("10.0.0.1"),
			expected: false,
		},
		{
			name:     "IPv4 loopback",
			ip:       net.ParseIP("127.0.0.1"),
			expected: false,
		},
		{
			name:     "nil IP",
			ip:       nil,
			expected: false,
		},
		{
			name:     "IPv6 link-local",
			ip:       net.ParseIP("fe80::1"),
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isIPv6(tc.ip)
			assert.Equal(t, tc.expected, result, "isIPv6(%v) should return %v", tc.ip, tc.expected)
		})
	}
}

// TestGetDefaultIPV6GW tests the getDefaultIPV6GW helper function
func TestGetDefaultIPV6GW(t *testing.T) {
	testCases := []struct {
		name       string
		subnet     string
		expectedGW string
	}{
		{
			name:       "standard /64 subnet",
			subnet:     "2001:db8::/64",
			expectedGW: "2001:db8::1",
		},
		{
			name:       "/48 subnet",
			subnet:     "2001:db8:abcd::/48",
			expectedGW: "2001:db8:abcd::1",
		},
		{
			name:       "/126 point-to-point subnet",
			subnet:     "2001:db8::4/126",
			expectedGW: "2001:db8::5",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, subnet, err := net.ParseCIDR(tc.subnet)
			require.NoError(t, err)

			// Convert to types.IPNet
			typesSubnet := types.IPNet{
				IP:   subnet.IP,
				Mask: subnet.Mask,
			}

			gw := getDefaultIPV6GW(typesSubnet)
			expectedGW := net.ParseIP(tc.expectedGW)
			assert.True(t, gw.Equal(expectedGW), "getDefaultIPV6GW(%s) should return %s, got %s", tc.subnet, tc.expectedGW, gw)
		})
	}
}

// TestIsIPv6NetworkAddress tests the isIPv6NetworkAddress helper function
func TestIsIPv6NetworkAddress(t *testing.T) {
	testCases := []struct {
		name     string
		subnet   string
		ip       string
		expected bool
	}{
		{
			name:     "network address of /64 subnet",
			subnet:   "2001:db8::/64",
			ip:       "2001:db8::",
			expected: true,
		},
		{
			name:     "first usable address of /64 subnet",
			subnet:   "2001:db8::/64",
			ip:       "2001:db8::1",
			expected: false,
		},
		{
			name:     "last address of /64 subnet (not broadcast in IPv6)",
			subnet:   "2001:db8::/64",
			ip:       "2001:db8::ffff:ffff:ffff:ffff",
			expected: false,
		},
		{
			name:     "network address of /126 subnet",
			subnet:   "2001:db8::4/126",
			ip:       "2001:db8::4",
			expected: true,
		},
		{
			name:     "usable address in /126 subnet",
			subnet:   "2001:db8::4/126",
			ip:       "2001:db8::5",
			expected: false,
		},
		{
			name:     "last address of /126 subnet (valid in IPv6)",
			subnet:   "2001:db8::4/126",
			ip:       "2001:db8::7",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, subnet, err := net.ParseCIDR(tc.subnet)
			require.NoError(t, err)

			ip := net.ParseIP(tc.ip)
			require.NotNil(t, ip)

			result := isIPv6NetworkAddress(*subnet, ip)
			assert.Equal(t, tc.expected, result, "isIPv6NetworkAddress(%s, %s) should return %v", tc.subnet, tc.ip, tc.expected)
		})
	}
}

// TestIPv6OnlyHappyPath tests valid IPv6-only configuration parsing
// Validates: Requirements 1.1, 1.2, 1.3, 1.4
func TestIPv6OnlyHappyPath(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipv6-address": "2001:db8::2/64",
				"ipv6-subnet": "2001:db8::/64",
				"ipv6-gateway": "2001:db8::1",
				"ipv6-routes": [
					{"dst": "fd00:ec2::254/128"}
				]
			}
		}`

	ipamConf, _, err := LoadIPAMConfig([]byte(conf), "")
	require.NoError(t, err, "valid IPv6-only configuration should not cause error")

	assert.Equal(t, net.ParseIP("2001:db8::1"), ipamConf.IPV6Gateway, "IPv6 gateway should be same as configured")
	assert.Equal(t, net.ParseIP("2001:db8::2"), ipamConf.IPV6Address.IP, "IPv6 address should be same as configured")
	assert.Equal(t, "fd00:ec2::254/128", ipamConf.IPV6Routes[0].Dst.String(), "IPv6 route should be same as configured")
	assert.True(t, ipamConf.HasIPv6(), "HasIPv6() should return true")
	assert.False(t, ipamConf.HasIPv4(), "HasIPv4() should return false for IPv6-only config")
}

// TestIPv6OnlyWithDefaultGateway tests IPv6-only configuration with default gateway calculation
// Validates: Requirements 1.5
func TestIPv6OnlyWithDefaultGateway(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipv6-address": "2001:db8::2/64",
				"ipv6-subnet": "2001:db8::/64"
			}
		}`

	ipamConf, _, err := LoadIPAMConfig([]byte(conf), "")
	require.NoError(t, err, "valid IPv6-only configuration should not cause error")

	expectedGW := net.ParseIP("2001:db8::1")
	assert.True(t, ipamConf.IPV6Gateway.Equal(expectedGW), "default IPv6 gateway should be first usable address in subnet, got %s", ipamConf.IPV6Gateway)
}

// TestDualStackHappyPath tests valid dual-stack configuration parsing
// Validates: Requirements 1.1-1.5, 2.3
func TestDualStackHappyPath(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"id": "container-12345",
				"ipv4-address": "10.0.0.2/24",
				"ipv4-subnet": "10.0.0.0/24",
				"ipv4-gateway": "10.0.0.1",
				"ipv4-routes": [
					{"dst": "169.254.170.2/32"}
				],
				"ipv6-address": "2001:db8::2/64",
				"ipv6-subnet": "2001:db8::/64",
				"ipv6-gateway": "2001:db8::1",
				"ipv6-routes": [
					{"dst": "fd00:ec2::254/128"}
				]
			}
		}`

	ipamConf, _, err := LoadIPAMConfig([]byte(conf), "")
	require.NoError(t, err, "valid dual-stack configuration should not cause error")

	// Verify IPv4 configuration
	assert.Equal(t, net.ParseIP("10.0.0.1").To4(), ipamConf.IPV4Gateway.To4(), "IPv4 gateway should be same as configured")
	assert.Equal(t, net.ParseIP("10.0.0.2").To4(), ipamConf.IPV4Address.IP.To4(), "IPv4 address should be same as configured")
	assert.Equal(t, "169.254.170.2/32", ipamConf.IPV4Routes[0].Dst.String(), "IPv4 route should be same as configured")

	// Verify IPv6 configuration
	assert.Equal(t, net.ParseIP("2001:db8::1"), ipamConf.IPV6Gateway, "IPv6 gateway should be same as configured")
	assert.Equal(t, net.ParseIP("2001:db8::2"), ipamConf.IPV6Address.IP, "IPv6 address should be same as configured")
	assert.Equal(t, "fd00:ec2::254/128", ipamConf.IPV6Routes[0].Dst.String(), "IPv6 route should be same as configured")

	// Verify helper methods
	assert.True(t, ipamConf.HasIPv4(), "HasIPv4() should return true for dual-stack config")
	assert.True(t, ipamConf.HasIPv6(), "HasIPv6() should return true for dual-stack config")
	assert.Equal(t, "container-12345", ipamConf.ID, "ID should be same as configured")
}

// TestDualStackWithDefaultGateways tests dual-stack configuration with default gateways
// Validates: Requirements 1.5
func TestDualStackWithDefaultGateways(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipv4-subnet": "10.0.0.0/24",
				"ipv6-subnet": "2001:db8::/64"
			}
		}`

	ipamConf, _, err := LoadIPAMConfig([]byte(conf), "")
	require.NoError(t, err, "valid dual-stack configuration should not cause error")

	// Verify default gateways
	expectedIPv4GW := net.ParseIP("10.0.0.1").To4()
	expectedIPv6GW := net.ParseIP("2001:db8::1")

	assert.Equal(t, expectedIPv4GW, ipamConf.IPV4Gateway.To4(), "default IPv4 gateway should be first usable address")
	assert.True(t, ipamConf.IPV6Gateway.Equal(expectedIPv6GW), "default IPv6 gateway should be first usable address")
}

// TestInvalidIPv6Address tests invalid IPv6 address format
// Validates: Requirements 4.1
func TestInvalidIPv6Address(t *testing.T) {
	testCases := []struct {
		name        string
		ipv6Address string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "invalid IPv6 address format",
			ipv6Address: "2001:db8::gggg/64",
			expectError: true,
			errorMsg:    "invalid IPv6 address format should cause error",
		},
		{
			name:        "IPv4 address in IPv6 field",
			ipv6Address: "10.0.0.2/24",
			expectError: true,
			errorMsg:    "IPv4 address in IPv6 field should cause error",
		},
		{
			name:        "missing prefix length",
			ipv6Address: "2001:db8::2",
			expectError: true,
			errorMsg:    "missing prefix length should cause error",
		},
		{
			name:        "valid IPv6 address",
			ipv6Address: "2001:db8::2/64",
			expectError: false,
			errorMsg:    "valid IPv6 address should not cause error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf := fmt.Sprintf(`{
				"name": "testnet",
				"cniVersion": "0.3.0",
				"ipam": {
					"type": "ipam",
					"ipv6-subnet": "2001:db8::/64",
					"ipv6-address": "%s"
				}
			}`, tc.ipv6Address)

			_, _, err := LoadIPAMConfig([]byte(conf), "")
			if tc.expectError {
				assert.Error(t, err, tc.errorMsg)
			} else {
				assert.NoError(t, err, tc.errorMsg)
			}
		})
	}
}

// TestIPv6AddressOutsideSubnet tests IPv6 address outside subnet validation
// Validates: Requirements 4.3
func TestIPv6AddressOutsideSubnet(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipv6-subnet": "2001:db8::/64",
				"ipv6-address": "2001:db9::2/64"
			}
		}`

	_, _, err := LoadIPAMConfig([]byte(conf), "")
	assert.Error(t, err, "IPv6 address outside subnet should cause error")
	assert.Contains(t, err.Error(), "not within the subnet", "error message should indicate address is not in subnet")
}

// TestIPv6GatewayOutsideSubnet tests IPv6 gateway outside subnet validation
// Validates: Requirements 4.4
func TestIPv6GatewayOutsideSubnet(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipv6-subnet": "2001:db8::/64",
				"ipv6-gateway": "2001:db9::1"
			}
		}`

	_, _, err := LoadIPAMConfig([]byte(conf), "")
	assert.Error(t, err, "IPv6 gateway outside subnet should cause error")
	assert.Contains(t, err.Error(), "not within the subnet", "error message should indicate gateway is not in subnet")
}

// TestIPv6NetworkAddressRejection tests that network address is rejected for IPv6
// Validates: Requirements 4.5
func TestIPv6NetworkAddressRejection(t *testing.T) {
	testCases := []struct {
		name     string
		conf     string
		errorMsg string
	}{
		{
			name: "IPv6 address is network address",
			conf: `{
				"name": "testnet",
				"cniVersion": "0.3.0",
				"ipam": {
					"type": "ipam",
					"ipv6-subnet": "2001:db8::/64",
					"ipv6-address": "2001:db8::/64"
				}
			}`,
			errorMsg: "IPv6 network address as IP should cause error",
		},
		{
			name: "IPv6 gateway is network address",
			conf: `{
				"name": "testnet",
				"cniVersion": "0.3.0",
				"ipam": {
					"type": "ipam",
					"ipv6-subnet": "2001:db8::/64",
					"ipv6-gateway": "2001:db8::"
				}
			}`,
			errorMsg: "IPv6 network address as gateway should cause error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := LoadIPAMConfig([]byte(tc.conf), "")
			assert.Error(t, err, tc.errorMsg)
			assert.Contains(t, err.Error(), "network address", "error message should indicate network address")
		})
	}
}

// TestIPv6LastAddressAllowed tests that last address in subnet is allowed (no broadcast in IPv6)
// Validates: Requirements 4.6
func TestIPv6LastAddressAllowed(t *testing.T) {
	// In IPv6, the last address in a subnet is valid (no broadcast)
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipv6-subnet": "2001:db8::4/126",
				"ipv6-address": "2001:db8::7/126"
			}
		}`

	ipamConf, _, err := LoadIPAMConfig([]byte(conf), "")
	require.NoError(t, err, "last address in IPv6 subnet should be allowed (no broadcast in IPv6)")
	assert.Equal(t, net.ParseIP("2001:db8::7"), ipamConf.IPV6Address.IP, "IPv6 address should be the last address in subnet")
}

// TestMissingBothSubnets tests that at least one subnet is required
// Validates: Requirements 2.4
func TestMissingBothSubnets(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipv4-gateway": "10.0.0.1",
				"ipv6-gateway": "2001:db8::1"
			}
		}`

	_, _, err := LoadIPAMConfig([]byte(conf), "")
	assert.Error(t, err, "missing both subnets should cause error")
	assert.Contains(t, err.Error(), "at least one subnet", "error message should indicate subnet is required")
}

// TestIPv6SubnetPrefixLengthValidation tests IPv6 subnet prefix length validation
// Validates: Requirements 4.2
func TestIPv6SubnetPrefixLengthValidation(t *testing.T) {
	testCases := []struct {
		name        string
		subnet      string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid /64 subnet",
			subnet:      "2001:db8::/64",
			expectError: false,
			errorMsg:    "valid /64 subnet should not cause error",
		},
		{
			name:        "valid /48 subnet",
			subnet:      "2001:db8::/48",
			expectError: false,
			errorMsg:    "valid /48 subnet should not cause error",
		},
		{
			name:        "valid /126 subnet (minimum)",
			subnet:      "2001:db8::/126",
			expectError: false,
			errorMsg:    "valid /126 subnet should not cause error",
		},
		{
			name:        "invalid /127 subnet (too small)",
			subnet:      "2001:db8::/127",
			expectError: true,
			errorMsg:    "/127 subnet should cause error (too small)",
		},
		{
			name:        "invalid /128 subnet (single host)",
			subnet:      "2001:db8::1/128",
			expectError: true,
			errorMsg:    "/128 subnet should cause error (single host)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf := fmt.Sprintf(`{
				"name": "testnet",
				"cniVersion": "0.3.0",
				"ipam": {
					"type": "ipam",
					"ipv6-subnet": "%s"
				}
			}`, tc.subnet)

			_, _, err := LoadIPAMConfig([]byte(conf), "")
			if tc.expectError {
				assert.Error(t, err, tc.errorMsg)
			} else {
				assert.NoError(t, err, tc.errorMsg)
			}
		})
	}
}

// TestHasIPv4AndHasIPv6Methods tests the HasIPv4() and HasIPv6() helper methods
func TestHasIPv4AndHasIPv6Methods(t *testing.T) {
	testCases := []struct {
		name       string
		conf       string
		expectIPv4 bool
		expectIPv6 bool
	}{
		{
			name: "IPv4 only",
			conf: `{
				"name": "testnet",
				"cniVersion": "0.3.0",
				"ipam": {
					"type": "ipam",
					"ipv4-subnet": "10.0.0.0/24"
				}
			}`,
			expectIPv4: true,
			expectIPv6: false,
		},
		{
			name: "IPv6 only",
			conf: `{
				"name": "testnet",
				"cniVersion": "0.3.0",
				"ipam": {
					"type": "ipam",
					"ipv6-subnet": "2001:db8::/64"
				}
			}`,
			expectIPv4: false,
			expectIPv6: true,
		},
		{
			name: "dual-stack",
			conf: `{
				"name": "testnet",
				"cniVersion": "0.3.0",
				"ipam": {
					"type": "ipam",
					"ipv4-subnet": "10.0.0.0/24",
					"ipv6-subnet": "2001:db8::/64"
				}
			}`,
			expectIPv4: true,
			expectIPv6: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ipamConf, _, err := LoadIPAMConfig([]byte(tc.conf), "")
			require.NoError(t, err, "valid configuration should not cause error")

			assert.Equal(t, tc.expectIPv4, ipamConf.HasIPv4(), "HasIPv4() should return %v", tc.expectIPv4)
			assert.Equal(t, tc.expectIPv6, ipamConf.HasIPv6(), "HasIPv6() should return %v", tc.expectIPv6)
		})
	}
}

// TestIPv6InvalidGatewayFormat tests invalid IPv6 gateway format
// Validates: Requirements 4.1
func TestIPv6InvalidGatewayFormat(t *testing.T) {
	testCases := []struct {
		name    string
		gateway string
	}{
		{
			name:    "IPv4 address as IPv6 gateway",
			gateway: "10.0.0.1",
		},
		{
			name:    "invalid IPv6 format",
			gateway: "2001:db8::gggg",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf := fmt.Sprintf(`{
				"name": "testnet",
				"cniVersion": "0.3.0",
				"ipam": {
					"type": "ipam",
					"ipv6-subnet": "2001:db8::/64",
					"ipv6-gateway": "%s"
				}
			}`, tc.gateway)

			_, _, err := LoadIPAMConfig([]byte(conf), "")
			assert.Error(t, err, "invalid IPv6 gateway format should cause error")
		})
	}
}

// TestIPv6WithRoutes tests IPv6 configuration with routes
// Validates: Requirements 1.4
func TestIPv6WithRoutes(t *testing.T) {
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipv6-subnet": "2001:db8::/64",
				"ipv6-routes": [
					{"dst": "fd00:ec2::254/128"},
					{"dst": "::/0", "gw": "2001:db8::1"}
				]
			}
		}`

	ipamConf, _, err := LoadIPAMConfig([]byte(conf), "")
	require.NoError(t, err, "valid IPv6 configuration with routes should not cause error")

	require.Len(t, ipamConf.IPV6Routes, 2, "should have 2 IPv6 routes")
	assert.Equal(t, "fd00:ec2::254/128", ipamConf.IPV6Routes[0].Dst.String(), "first route destination should match")
	assert.Equal(t, "::/0", ipamConf.IPV6Routes[1].Dst.String(), "second route destination should match")
	assert.Equal(t, net.ParseIP("2001:db8::1"), ipamConf.IPV6Routes[1].GW, "second route gateway should match")
}
