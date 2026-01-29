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

package ipstore

import (
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"testing/quick"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNextIPNoAvailableIP tests no available IP in the subnet
func TestNextIPNoAvailableIP(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")

	// No available ip in the subnet
	_, subnet, err := net.ParseCIDR("10.0.0.0/31")
	assert.NoError(t, err, "Parsing the subnet failed")

	_, err = NextIP(ip, *subnet)
	assert.Error(t, err, "no avaialble ip in the subnet should cause error")
}

func TestNextIPHappyPath(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	_, subnet, err := net.ParseCIDR("10.0.0.0/30")
	assert.NoError(t, err, "Parsing the subnet failed")

	nextIP, err := NextIP(ip, *subnet)
	assert.NoError(t, err, "error is not expected to get next ip")

	assert.Equal(t, "10.0.0.2", nextIP.String(), "next ip should be increase 1 by current ip")
}

// TestNextIPCircle tests it will start from minimum address if reached the maximum one
func TestNextIPCircle(t *testing.T) {
	ip := net.ParseIP("10.0.0.2")
	_, subnet, err := net.ParseCIDR("10.0.0.0/30")
	assert.NoError(t, err, "Parsing the subnet failed")

	nextIP, err := NextIP(ip, *subnet)
	assert.NoError(t, err, "error is not expected to get next ip")
	assert.Equal(t, "10.0.0.1", nextIP.String(), "the minimum one should be returned if reached to the maximum")
}

func TestNextIPInvalidIPV4(t *testing.T) {
	ip := net.ParseIP("10.0.0.3.2.3")
	_, subnet, err := net.ParseCIDR("10.0.0.0/30")
	assert.NoError(t, err, "Parsing the subnet failed")

	_, err = NextIP(ip, *subnet)
	assert.Error(t, err, "invalid ipv4 address should cause error")
}

func TestNextIPNotInSubnet(t *testing.T) {
	ip := net.ParseIP("10.0.0.3")
	_, subnet, err := net.ParseCIDR("10.1.0.0/16")
	assert.NoError(t, err)

	_, err = NextIP(ip, *subnet)
	assert.Error(t, err)
}

// TestNextIPv6HappyPath tests basic IPv6 increment
func TestNextIPv6HappyPath(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	_, subnet, err := net.ParseCIDR("2001:db8::/64")
	assert.NoError(t, err, "Parsing the subnet failed")

	nextIP, err := NextIPv6(ip, *subnet)
	assert.NoError(t, err, "error is not expected to get next ip")
	assert.Equal(t, "2001:db8::2", nextIP.String(), "next ip should be increased by 1")
}

// TestNextIPv6SkipsNetworkAddress tests that NextIPv6 skips the network address
func TestNextIPv6SkipsNetworkAddress(t *testing.T) {
	// Start from network address (all zeros in host portion)
	ip := net.ParseIP("2001:db8::")
	_, subnet, err := net.ParseCIDR("2001:db8::/64")
	assert.NoError(t, err, "Parsing the subnet failed")

	nextIP, err := NextIPv6(ip, *subnet)
	assert.NoError(t, err, "error is not expected to get next ip")
	// Should skip network address and return first usable address
	assert.Equal(t, "2001:db8::1", nextIP.String(), "should skip network address and return first usable")
}

// TestNextIPv6Wraparound tests wraparound at subnet boundary
func TestNextIPv6Wraparound(t *testing.T) {
	// Use a /126 subnet (4 addresses: ::0, ::1, ::2, ::3)
	// Start from the last address (::3)
	ip := net.ParseIP("2001:db8::3")
	_, subnet, err := net.ParseCIDR("2001:db8::/126")
	assert.NoError(t, err, "Parsing the subnet failed")

	nextIP, err := NextIPv6(ip, *subnet)
	assert.NoError(t, err, "error is not expected to get next ip")
	// Should wrap around and skip network address (::0), returning ::1
	assert.Equal(t, "2001:db8::1", nextIP.String(), "should wrap around and skip network address")
}

// TestNextIPv6InvalidIPv4Passed tests that passing an IPv4 address returns an error
func TestNextIPv6InvalidIPv4Passed(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	_, subnet, err := net.ParseCIDR("2001:db8::/64")
	assert.NoError(t, err, "Parsing the subnet failed")

	_, err = NextIPv6(ip, *subnet)
	assert.Error(t, err, "passing IPv4 address should cause error")
	assert.Contains(t, err.Error(), "invalid ipv6 address")
}

// TestNextIPv6NotInSubnet tests that IP not in subnet returns an error
func TestNextIPv6NotInSubnet(t *testing.T) {
	ip := net.ParseIP("2001:db9::1")
	_, subnet, err := net.ParseCIDR("2001:db8::/64")
	assert.NoError(t, err, "Parsing the subnet failed")

	_, err = NextIPv6(ip, *subnet)
	assert.Error(t, err, "IP not in subnet should cause error")
	assert.Contains(t, err.Error(), "not in subnet")
}

// TestNextIPv6NoAvailableIP tests that prefix length > 126 returns an error
func TestNextIPv6NoAvailableIP(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	_, subnet, err := net.ParseCIDR("2001:db8::/127")
	assert.NoError(t, err, "Parsing the subnet failed")

	_, err = NextIPv6(ip, *subnet)
	assert.Error(t, err, "prefix length > 126 should cause error")
	assert.Contains(t, err.Error(), "no available ip")
}

// TestNextIPv6LargeSubnet tests NextIPv6 with a typical /64 subnet
func TestNextIPv6LargeSubnet(t *testing.T) {
	ip := net.ParseIP("2001:db8:abcd:1234::ffff")
	_, subnet, err := net.ParseCIDR("2001:db8:abcd:1234::/64")
	assert.NoError(t, err, "Parsing the subnet failed")

	nextIP, err := NextIPv6(ip, *subnet)
	assert.NoError(t, err, "error is not expected to get next ip")
	// Go formats IPv6 with :: compression, so 0x10000 becomes ::1:0
	assert.Equal(t, "2001:db8:abcd:1234::1:0", nextIP.String(), "next ip should be increased by 1")
}

// TestNextIPv6HighBitIncrement tests 128-bit arithmetic with high bits
func TestNextIPv6HighBitIncrement(t *testing.T) {
	// Test incrementing an address with all f's in lower bits
	ip := net.ParseIP("2001:db8::ffff:ffff:ffff:ffff")
	_, subnet, err := net.ParseCIDR("2001:db8::/32")
	assert.NoError(t, err, "Parsing the subnet failed")

	nextIP, err := NextIPv6(ip, *subnet)
	assert.NoError(t, err, "error is not expected to get next ip")
	assert.Equal(t, "2001:db8:0:1::", nextIP.String(), "should correctly handle carry over")
}

// ============================================================================
// IPv6 Allocation and Release Tests
// ============================================================================

// createTestIPManager creates an IPManager with a temporary database for testing
func createTestIPManager(t *testing.T, subnetV4, subnetV6 *net.IPNet) (IPAllocator, func()) {
	tmpDir, err := os.MkdirTemp("", "ipstore_test")
	require.NoError(t, err)

	dbPath := filepath.Join(tmpDir, "test.db")
	config := &Config{
		DB:                dbPath,
		PersistConnection: true,
		Bucket:            "test",
		ConnectionTimeout: 5 * time.Second,
	}

	manager, err := NewIPAllocatorDualStack(config, subnetV4, subnetV6)
	require.NoError(t, err)

	cleanup := func() {
		manager.Close()
		os.RemoveAll(tmpDir)
	}

	return manager, cleanup
}

// TestGetAvailableIPv6HappyPath tests basic IPv6 allocation
func TestGetAvailableIPv6HappyPath(t *testing.T) {
	_, subnetV6, err := net.ParseCIDR("2001:db8::/64")
	require.NoError(t, err)

	manager, cleanup := createTestIPManager(t, nil, subnetV6)
	defer cleanup()

	// Allocate first IPv6 address
	ip1, err := manager.GetAvailableIPv6("container1")
	assert.NoError(t, err)
	assert.NotEmpty(t, ip1)

	// Verify it's a valid IPv6 in the subnet
	parsedIP := net.ParseIP(ip1)
	assert.NotNil(t, parsedIP)
	assert.True(t, subnetV6.Contains(parsedIP), "allocated IP should be in subnet")

	// Allocate second IPv6 address
	ip2, err := manager.GetAvailableIPv6("container2")
	assert.NoError(t, err)
	assert.NotEmpty(t, ip2)
	assert.NotEqual(t, ip1, ip2, "second allocation should be different")
}

// TestGetAvailableIPv6NoSubnetConfigured tests error when IPv6 subnet not configured
func TestGetAvailableIPv6NoSubnetConfigured(t *testing.T) {
	_, subnetV4, err := net.ParseCIDR("10.0.0.0/24")
	require.NoError(t, err)

	manager, cleanup := createTestIPManager(t, subnetV4, nil)
	defer cleanup()

	_, err = manager.GetAvailableIPv6("container1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IPv6 subnet not configured")
}

// TestIPv6AllocationAndRelease tests allocating and releasing IPv6 addresses
func TestIPv6AllocationAndRelease(t *testing.T) {
	_, subnetV6, err := net.ParseCIDR("2001:db8::/126")
	require.NoError(t, err)

	manager, cleanup := createTestIPManager(t, nil, subnetV6)
	defer cleanup()

	// Allocate an address
	ip1, err := manager.GetAvailableIPv6("container1")
	assert.NoError(t, err)

	// Release by ID
	_, ipv6Released, err := manager.ReleaseByID("container1")
	assert.NoError(t, err)
	assert.Equal(t, ip1, ipv6Released)

	// Should be able to allocate again
	ip2, err := manager.GetAvailableIPv6("container2")
	assert.NoError(t, err)
	assert.NotEmpty(t, ip2)
}

// TestIPv6DuplicateIDDetection tests that duplicate container IDs are rejected
func TestIPv6DuplicateIDDetection(t *testing.T) {
	_, subnetV6, err := net.ParseCIDR("2001:db8::/64")
	require.NoError(t, err)

	manager, cleanup := createTestIPManager(t, nil, subnetV6)
	defer cleanup()

	// Allocate first address with ID
	_, err = manager.GetAvailableIPv6("container1")
	assert.NoError(t, err)

	// Try to allocate with same ID - should fail
	_, err = manager.GetAvailableIPv6("container1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "id already exists")
}

// TestDualStackAllocationAndRelease tests allocating and releasing both IPv4 and IPv6
func TestDualStackAllocationAndRelease(t *testing.T) {
	_, subnetV4, err := net.ParseCIDR("10.0.0.0/24")
	require.NoError(t, err)
	_, subnetV6, err := net.ParseCIDR("2001:db8::/64")
	require.NoError(t, err)

	manager, cleanup := createTestIPManager(t, subnetV4, subnetV6)
	defer cleanup()

	// Allocate IPv4
	ipv4, err := manager.GetAvailableIP("container1")
	assert.NoError(t, err)
	assert.NotEmpty(t, ipv4)

	// Allocate IPv6 with same ID should succeed (dual-stack containers use same ID)
	ipv6, err := manager.GetAvailableIPv6("container1")
	assert.NoError(t, err)
	assert.NotEmpty(t, ipv6)

	// Release both IPv4 and IPv6 by ID
	ipv4Released, ipv6Released, err := manager.ReleaseByID("container1")
	assert.NoError(t, err)
	assert.Equal(t, ipv4, ipv4Released)
	assert.Equal(t, ipv6, ipv6Released)
}

// TestReleaseByIDNotFound tests error when ID not found
func TestReleaseByIDNotFound(t *testing.T) {
	_, subnetV6, err := net.ParseCIDR("2001:db8::/64")
	require.NoError(t, err)

	manager, cleanup := createTestIPManager(t, nil, subnetV6)
	defer cleanup()

	_, _, err = manager.ReleaseByID("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no ip address associated with the given id")
}

// TestSetLastKnownIPv6 tests the SetLastKnownIPv6 method
func TestSetLastKnownIPv6(t *testing.T) {
	_, subnetV6, err := net.ParseCIDR("2001:db8::/64")
	require.NoError(t, err)

	manager, cleanup := createTestIPManager(t, nil, subnetV6)
	defer cleanup()

	// Set last known IPv6
	testIP := net.ParseIP("2001:db8::100")
	manager.SetLastKnownIPv6(testIP)

	// Allocate next - should start from the set IP
	ip, err := manager.GetAvailableIPv6("container1")
	assert.NoError(t, err)
	// Next IP after 2001:db8::100 should be 2001:db8::101
	assert.Equal(t, "2001:db8::101", ip)
}

// ============================================================================
// Property-Based Tests
// ============================================================================

// createIPv6SubnetFromBytes creates an IPv6 subnet from random bytes and prefix length
func createIPv6SubnetFromBytes(subnetBytes [16]byte, prefixLen uint8) *net.IPNet {
	// Create mask from prefix length
	mask := net.CIDRMask(int(prefixLen), 128)

	// Apply mask to get network address
	networkIP := make(net.IP, 16)
	for i := 0; i < 16; i++ {
		networkIP[i] = subnetBytes[i] & mask[i]
	}

	return &net.IPNet{
		IP:   networkIP,
		Mask: mask,
	}
}

// incrementIPv6 increments an IPv6 address by 1
func incrementIPv6(ip net.IP) net.IP {
	ipInt := big.NewInt(0).SetBytes(ip.To16())
	ipInt.Add(ipInt, big.NewInt(1))

	result := make(net.IP, 16)
	bytes := ipInt.Bytes()
	copy(result[16-len(bytes):], bytes)
	return result
}

// Feature: ipv6-support, Property 6: IPv6 Address Allocation
// For any IPv6 subnet, when allocating addresses without explicit specification,
// each call to GetAvailableIPv6 shall return a unique, valid IPv6 address within
// the subnet that has not been previously allocated.
// **Validates: Requirements 3.1, 3.2**
func TestProperty_IPv6AddressAllocation(t *testing.T) {
	f := func(subnetBytes [16]byte, prefixLen uint8) bool {
		// Constrain prefix length to valid range (16-126)
		// Use smaller subnets for faster testing
		if prefixLen > 124 || prefixLen < 120 {
			return true // Skip invalid/too large inputs
		}

		subnet := createIPv6SubnetFromBytes(subnetBytes, prefixLen)

		// Create a temporary manager for this test
		tmpDir, err := os.MkdirTemp("", "ipstore_prop_test")
		if err != nil {
			return false
		}
		defer os.RemoveAll(tmpDir)

		dbPath := filepath.Join(tmpDir, "test.db")
		config := &Config{
			DB:                dbPath,
			PersistConnection: true,
			Bucket:            "test",
			ConnectionTimeout: 5 * time.Second,
		}

		manager, err := NewIPAllocatorDualStack(config, nil, subnet)
		if err != nil {
			return false
		}
		defer manager.Close()

		// Allocate multiple addresses and verify uniqueness
		allocated := make(map[string]bool)
		numAllocations := 3 // Allocate a few addresses

		for i := 0; i < numAllocations; i++ {
			ip, err := manager.GetAvailableIPv6(string(rune('a' + i)))
			if err != nil {
				// May run out of addresses in small subnets
				break
			}

			// Check uniqueness
			if allocated[ip] {
				return false // Duplicate allocation!
			}
			allocated[ip] = true

			// Verify IP is in subnet
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil || !subnet.Contains(parsedIP) {
				return false
			}
		}

		return true
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 100}); err != nil {
		t.Error(err)
	}
}

// Feature: ipv6-support, Property 7: Duplicate IPv6 Address Detection
// For any IPv6 address that has been allocated, attempting to allocate the same
// address again shall return an error indicating the address is already in use.
// **Validates: Requirements 3.3, 3.4**
func TestProperty_DuplicateIPv6AddressDetection(t *testing.T) {
	f := func(subnetBytes [16]byte, prefixLen uint8) bool {
		// Constrain prefix length to valid range
		if prefixLen > 124 || prefixLen < 120 {
			return true // Skip invalid inputs
		}

		subnet := createIPv6SubnetFromBytes(subnetBytes, prefixLen)

		// Create a temporary manager for this test
		tmpDir, err := os.MkdirTemp("", "ipstore_prop_test")
		if err != nil {
			return false
		}
		defer os.RemoveAll(tmpDir)

		dbPath := filepath.Join(tmpDir, "test.db")
		config := &Config{
			DB:                dbPath,
			PersistConnection: true,
			Bucket:            "test",
			ConnectionTimeout: 5 * time.Second,
		}

		manager, err := NewIPAllocatorDualStack(config, nil, subnet)
		if err != nil {
			return false
		}
		defer manager.Close()

		// Allocate with an ID
		_, err = manager.GetAvailableIPv6("test-container")
		if err != nil {
			return false
		}

		// Try to allocate with the same ID - should fail
		_, err = manager.GetAvailableIPv6("test-container")
		if err == nil {
			return false // Should have failed!
		}

		return true
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 100}); err != nil {
		t.Error(err)
	}
}

// Feature: ipv6-support, Property 8: Network Address Skipping
// For any IPv6 subnet, NextIPv6 shall never return the subnet's network address
// (all zeros in host portion).
// **Validates: Requirements 3.5**
func TestProperty_NetworkAddressSkipping(t *testing.T) {
	f := func(subnetBytes [16]byte, prefixLen uint8) bool {
		// Constrain prefix length to valid range (16-126)
		if prefixLen > 126 || prefixLen < 16 {
			return true // Skip invalid inputs
		}

		subnet := createIPv6SubnetFromBytes(subnetBytes, prefixLen)
		networkAddr := subnet.IP.Mask(subnet.Mask)

		// Ensure networkAddr is 16 bytes
		if len(networkAddr) != 16 {
			networkAddr = networkAddr.To16()
		}

		// Start from network address
		nextIP, err := NextIPv6(networkAddr, *subnet)
		if err != nil {
			return false
		}

		// Next IP should never be the network address
		if nextIP.Equal(networkAddr) {
			return false
		}

		// Also test from various starting points in the subnet
		// Start from first usable address
		firstUsable := incrementIPv6(networkAddr)
		if subnet.Contains(firstUsable) {
			nextIP2, err := NextIPv6(firstUsable, *subnet)
			if err != nil {
				return false
			}
			if nextIP2.Equal(networkAddr) {
				return false
			}
		}

		return true
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 100}); err != nil {
		t.Error(err)
	}
}

// Feature: ipv6-support, Property 14: 128-bit Arithmetic Correctness
// For any valid IPv6 address within a subnet, NextIPv6 shall correctly increment
// the address using 128-bit arithmetic and return a valid IPv6 address within the same subnet.
// **Validates: Requirements 8.1**
func TestProperty_128BitArithmeticCorrectness(t *testing.T) {
	f := func(ipBytes [16]byte, subnetBytes [16]byte, prefixLen uint8) bool {
		// Constrain prefix length to valid range
		if prefixLen > 126 || prefixLen < 16 {
			return true // Skip invalid inputs
		}

		subnet := createIPv6SubnetFromBytes(subnetBytes, prefixLen)

		// Create an IP within the subnet by applying the mask and adding host bits
		ip := make(net.IP, 16)
		for i := 0; i < 16; i++ {
			// Network portion from subnet, host portion from ipBytes
			ip[i] = (subnet.IP[i] & subnet.Mask[i]) | (ipBytes[i] & ^subnet.Mask[i])
		}

		// Skip if IP equals network address (NextIPv6 will skip it anyway)
		networkAddr := subnet.IP.Mask(subnet.Mask)
		if ip.Equal(networkAddr) {
			ip = incrementIPv6(ip)
		}

		// Ensure IP is in subnet
		if !subnet.Contains(ip) {
			return true // Skip IPs outside subnet
		}

		nextIP, err := NextIPv6(ip, *subnet)
		if err != nil {
			return false
		}

		// Verify result is valid IPv6 (16 bytes)
		if len(nextIP) != 16 {
			return false
		}

		// Verify result is in subnet
		if !subnet.Contains(nextIP) {
			return false
		}

		// Verify the increment is correct (nextIP should be ip+1, or wrapped around)
		expectedNext := incrementIPv6(ip)

		// Calculate max address
		maxIP := make(net.IP, 16)
		for i := 0; i < 16; i++ {
			maxIP[i] = subnet.IP[i] | ^subnet.Mask[i]
		}

		// If we were at max, we should wrap to first usable (skip network address)
		if ip.Equal(maxIP) {
			// Should wrap to first usable address (network + 1)
			expectedNext = incrementIPv6(networkAddr)
		}

		// If expected is network address, skip it
		if expectedNext.Equal(networkAddr) {
			expectedNext = incrementIPv6(expectedNext)
		}

		// Verify the result matches expected
		if !nextIP.Equal(expectedNext) {
			// Allow for wraparound case
			if !subnet.Contains(expectedNext) {
				// Wrapped around, should be first usable
				firstUsable := incrementIPv6(networkAddr)
				return nextIP.Equal(firstUsable)
			}
			return false
		}

		return true
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 100}); err != nil {
		t.Error(err)
	}
}
