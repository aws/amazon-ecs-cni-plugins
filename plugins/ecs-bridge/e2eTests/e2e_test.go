//go:build e2e
// +build e2e

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

package e2eTests

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"runtime"
	"strconv"
	"testing"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

const (
	bridgeName            = "ecs-test-bridge"
	ifName                = "ecs-test-eth0"
	containerID           = "contain-er"
	expectedBridgeAddress = "169.254.172.1/22"
	expectedGateway       = "169.254.172.1"
	expectedVethAddress   = "169.254.172.2/22"
	dst                   = "169.254.170.2/32"
	bridgeDst             = "169.254.172.1/32"
	netConf               = `
{
    "type":"ecs-bridge",
    "cniVersion":"0.3.0",
    "bridge":"%s",
    "ipam":{
	"type":"ecs-ipam",
	"id":"test",
	"cniVersion":"0.3.0",
	"ipv4-subnet":"169.254.172.0/22",
	"ipv4-routes":[
	    {
		"dst":"%s"
	    }
	]
    }
}`

	// IPv6-only configuration
	expectedBridgeAddressIPv6 = "2001:db8::1/64"
	expectedGatewayIPv6       = "2001:db8::1"
	expectedVethAddressIPv6   = "2001:db8::2/64"
	dstIPv6                   = "fd00:ec2::254/128"
	bridgeDstIPv6             = "2001:db8::1/128"
	netConfIPv6               = `
{
    "type":"ecs-bridge",
    "cniVersion":"0.3.0",
    "bridge":"%s",
    "ipam":{
	"type":"ecs-ipam",
	"id":"test-ipv6",
	"cniVersion":"0.3.0",
	"ipv6-subnet":"2001:db8::/64",
	"ipv6-routes":[
	    {
		"dst":"%s"
	    }
	]
    }
}`

	// Dual-stack configuration
	netConfDualStack = `
{
    "type":"ecs-bridge",
    "cniVersion":"0.3.0",
    "bridge":"%s",
    "ipam":{
	"type":"ecs-ipam",
	"id":"test-dualstack",
	"cniVersion":"0.3.0",
	"ipv4-subnet":"169.254.172.0/22",
	"ipv4-routes":[
	    {
		"dst":"169.254.170.2/32"
	    }
	],
	"ipv6-subnet":"2001:db8::/64",
	"ipv6-routes":[
	    {
		"dst":"fd00:ec2::254/128"
	    }
	]
    }
}`

	// ECS dual-stack configuration: IPv4 link-local for credentials endpoint + IPv6 default gateway
	// This is the typical ECS configuration where:
	// - IPv4 link-local (169.254.x.x) provides access to the ECS credentials endpoint
	// - IPv6 provides the default gateway for internet access
	netConfECSDualStack = `
{
    "type":"ecs-bridge",
    "cniVersion":"0.3.0",
    "bridge":"%s",
    "ipam":{
	"type":"ecs-ipam",
	"id":"test-ecs-dualstack",
	"cniVersion":"0.3.0",
	"ipv4-subnet":"169.254.172.0/22",
	"ipv4-routes":[
	    {
		"dst":"169.254.170.2/32"
	    }
	],
	"ipv6-subnet":"2001:db8::/64",
	"ipv6-routes":[
	    {
		"dst":"::/0"
	    }
	]
    }
}`

	// ============================================================================
	// Daemon Host Namespace Test Constants
	// These constants are used for testing daemon host namespace connectivity
	// with IPv4 link-local for ECS credentials and IPv6 for external traffic
	// ============================================================================

	// Daemon namespace identifiers
	daemonBridgeName  = "ecs-dmn-bridge"
	daemonIfName      = "ecs-daemon-eth0"
	daemonContainerID = "daemon-host-ns"

	// ECS link-local subnet (always IPv4) - used for credentials endpoint access
	ecsLinkLocalSubnet        = "169.254.172.0/22"
	ecsLinkLocalGateway       = "169.254.172.1"
	ecsCredentialsEndpointDst = "169.254.170.2/32"

	// Expected daemon bridge addresses
	expectedDaemonBridgeIPv4 = "169.254.172.1/22"
	expectedDaemonBridgeIPv6 = "2001:db8:1::1/64"

	// Expected daemon veth addresses (allocated from subnets)
	expectedDaemonVethIPv4 = "169.254.172.2/22"
	expectedDaemonVethIPv6 = "2001:db8:1::2/64"

	// IPv6 configuration for external traffic
	// Note: Using 2001:db8:1::/64 which is a valid IPv6 documentation prefix
	// (2001:db8::/32 is reserved for documentation per RFC 3849)
	daemonIPv6Subnet  = "2001:db8:1::/64"
	daemonIPv6Gateway = "2001:db8:1::1"

	// ============================================================================
	// Daemon Host Namespace CNI Configuration Templates
	// ============================================================================

	// netConfDaemonIPv4Only is the CNI configuration for IPv4-only daemon namespace
	// This configuration provides:
	// - IPv4 link-local subnet (169.254.172.0/22) for ECS credentials endpoint access
	// - Route to ECS credentials endpoint (169.254.170.2/32)
	// - Default route (0.0.0.0/0) for external traffic via IPv4
	netConfDaemonIPv4Only = `
{
    "type":"ecs-bridge",
    "cniVersion":"0.3.0",
    "bridge":"%s",
    "ipam":{
        "type":"ecs-ipam",
        "id":"daemon-ipv4",
        "cniVersion":"0.3.0",
        "ipv4-subnet":"169.254.172.0/22",
        "ipv4-routes":[
            {"dst":"169.254.170.2/32"},
            {"dst":"0.0.0.0/0"}
        ]
    }
}`

	// netConfDaemonIPv6Only is the CNI configuration for IPv6-only daemon namespace
	// This is the key configuration for exposing IPv6 bugs in the ecs-bridge implementation.
	// This configuration provides:
	// - IPv4 link-local subnet (169.254.172.0/22) for ECS credentials endpoint access
	//   (ECS credentials endpoint is always IPv4 link-local, even on IPv6-only hosts)
	// - Route to ECS credentials endpoint (169.254.170.2/32) via IPv4 link-local
	// - IPv6 subnet (2001:db8:1::/64) for external traffic
	// - IPv6 default route (::/0) for external traffic via IPv6
	netConfDaemonIPv6Only = `
{
    "type":"ecs-bridge",
    "cniVersion":"0.3.0",
    "bridge":"%s",
    "ipam":{
        "type":"ecs-ipam",
        "id":"daemon-ipv6",
        "cniVersion":"0.3.0",
        "ipv4-subnet":"169.254.172.0/22",
        "ipv4-routes":[
            {"dst":"169.254.170.2/32"}
        ],
        "ipv6-subnet":"2001:db8:1::/64",
        "ipv6-routes":[
            {"dst":"::/0"}
        ]
    }
}`

	// netConfDaemonDualStack is the CNI configuration for dual-stack daemon namespace
	// This configuration is for dual-stack hosts with IPv4 link-local for ECS credentials
	// and IPv6 for external traffic routing.
	// This configuration provides:
	// - IPv4 link-local subnet (169.254.172.0/22) for ECS credentials endpoint access
	// - Route to ECS credentials endpoint (169.254.170.2/32) via IPv4 link-local
	// - IPv6 subnet (2001:db8:1::/64) for external traffic
	// - IPv6 default route (::/0) for external traffic via IPv6
	netConfDaemonDualStack = `
{
    "type":"ecs-bridge",
    "cniVersion":"0.3.0",
    "bridge":"%s",
    "ipam":{
        "type":"ecs-ipam",
        "id":"daemon-dualstack",
        "cniVersion":"0.3.0",
        "ipv4-subnet":"169.254.172.0/22",
        "ipv4-routes":[
            {"dst":"169.254.170.2/32"}
        ],
        "ipv6-subnet":"2001:db8:1::/64",
        "ipv6-routes":[
            {"dst":"::/0"}
        ]
    }
}`
)

func init() {
	// This is to ensure that all the namespace operations are performed for
	// a single thread
	runtime.LockOSThread()
}

// instanceSupportsIPv4 checks if the instance has IPv4 support by looking for
// non-loopback IPv4 addresses on any interface
func instanceSupportsIPv4() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		// Skip loopback interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			// Check for IPv4 address (not link-local 169.254.x.x which might be auto-configured)
			if ipNet.IP.To4() != nil && !ipNet.IP.IsLinkLocalUnicast() {
				return true
			}
		}
	}
	return false
}

// instanceSupportsIPv6 checks if the instance has IPv6 support by looking for
// non-loopback, non-link-local IPv6 addresses on any interface
func instanceSupportsIPv6() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		// Skip loopback interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			// Check for IPv6 address (not link-local fe80::)
			if ipNet.IP.To4() == nil && ipNet.IP.To16() != nil && !ipNet.IP.IsLinkLocalUnicast() {
				return true
			}
		}
	}
	return false
}

// skipIfNoIPv4 skips the test if the instance doesn't support IPv4
func skipIfNoIPv4(t *testing.T) {
	if !instanceSupportsIPv4() {
		t.Skip("Skipping test: instance does not have IPv4 support")
	}
}

// skipIfNoIPv6 skips the test if the instance doesn't support IPv6
func skipIfNoIPv6(t *testing.T) {
	if !instanceSupportsIPv6() {
		t.Skip("Skipping test: instance does not have IPv6 support")
	}
}

// skipIfNoDualStack skips the test if the instance doesn't support both IPv4 and IPv6
func skipIfNoDualStack(t *testing.T) {
	if !instanceSupportsIPv4() || !instanceSupportsIPv6() {
		t.Skip("Skipping test: instance does not have dual-stack (IPv4 + IPv6) support")
	}
}

// configureNetNSFunc function type defines a method that configures the network
// namespace before executing the "ADD" command
type configureNetNSFunc func() error

func TestAddDel(t *testing.T) {
	// Skip if instance doesn't support IPv4
	skipIfNoIPv4(t)

	testCases := map[string]configureNetNSFunc{
		"When Bridge Exists": configureNetNSWithBridge,
		"When Bridge Exists And Configured With IP Address": configureNetNSWithBridgeAndSetIPAddress,
		"When Bridge Does Not Exist":                        configureNetNSNop,
	}

	// Ensure that the bridge plugin exists
	bridgePluginPath, err := invoke.FindInPath("ecs-bridge", []string{os.Getenv("CNI_PATH")})
	require.NoError(t, err, "Unable to find bridge plugin in path")

	// Create a directory for storing test logs
	testLogDir, err := ioutil.TempDir("", "ecs-bridge-e2e-test-")
	require.NoError(t, err, "Unable to create directory for storing test logs")

	// Configure the env var to use the test logs directory
	os.Setenv("ECS_CNI_LOG_FILE", fmt.Sprintf("%s/bridge.log", testLogDir))
	t.Logf("Using %s for test logs", testLogDir)
	defer os.Unsetenv("ECS_CNI_LOG_FILE")

	// Handle deletion of test logs at the end of the test execution if
	// specified
	ok, err := strconv.ParseBool(getEnvOrDefault("ECS_PRESERVE_E2E_TEST_LOGS", "false"))
	assert.NoError(t, err, "Unable to parse ECS_PRESERVE_E2E_TEST_LOGS env var")
	defer func(preserve bool) {
		if !t.Failed() && !preserve {
			os.RemoveAll(testLogDir)
		}
	}(ok)

	// Execute test cases
	for tcName, configFunc := range testCases {
		t.Run(tcName, func(t *testing.T) {
			// Create a network namespace to execute the test in.
			// The bridge and veth pairs will be created in this namespace
			testNS, err := ns.NewNS()
			require.NoError(t, err, "Unable to create the network namespace to run the test in")
			defer testNS.Close()

			// Create a network namespace to mimic the container's network namespace.
			// One end of the veth pair device will be moved to this namespace
			targetNS, err := ns.NewNS()
			require.NoError(t, err,
				"Unable to create the network namespace that represents the network namespace of the container")
			defer targetNS.Close()

			// Create a directory to store IPAM db
			ipamDir, err := ioutil.TempDir("", "ecs-ipam-")
			require.NoError(t, err, "Unable to create a temp directory for the ipam db")
			os.Setenv("IPAM_DB_PATH", fmt.Sprintf("%s/ipam.db", ipamDir))
			defer os.Unsetenv("IPAM_DB_PATH")
			ok, err := strconv.ParseBool(getEnvOrDefault("ECS_BRIDGE_PRESERVE_IPAM_DB", "false"))
			assert.NoError(t, err, "Unable to parse ECS_BRIDGE_PRESERVE_IPAM_DB env var")
			if !ok {
				defer os.RemoveAll(ipamDir)
			}

			// Construct args to invoke the CNI plugin with
			execInvokeArgs := &invoke.Args{
				ContainerID: containerID,
				NetNS:       targetNS.Path(),
				IfName:      ifName,
				Path:        os.Getenv("CNI_PATH"),
			}
			// vethTestNetNS is a placeholder that will be populated during execution
			// of the "ADD" command with details of the veth pair device created
			var vethTestNetNS netlink.Link
			testNS.Do(func(ns.NetNS) error {
				err = configFunc()
				require.NoError(t, err, "Unable to configure test netns before executing ADD")

				// Execute the "ADD" command for the plugin
				execInvokeArgs.Command = "ADD"
				_, err := invoke.ExecPluginWithResult(
					bridgePluginPath,
					[]byte(fmt.Sprintf(netConf, bridgeName, dst)),
					execInvokeArgs)
				require.NoError(t, err, "Unable to execute ADD command for ecs-bridge plugin")

				// Validate that bridge was created with the expected address
				bridge := getBridgeLink(t)
				validateBridgeAddress(t, bridge)
				// Validate that veth pair device was created
				vethTestNetNS, ok = getVethAndVerifyLo(t)
				require.True(t, ok, "veth device not found in test netns")
				return nil
			})

			var vethTargetNetNS netlink.Link
			targetNS.Do(func(ns.NetNS) error {
				// Validate the other end of the veth pair device has the desired
				// route and the address allocated to it
				vethTargetNetNS, ok = getVethAndVerifyLo(t)
				require.True(t, ok, "veth device not found in target netns")
				validateVethAddress(t, vethTargetNetNS)
				validateRouteForVethInTargetNetNS(t, vethTargetNetNS)
				return nil
			})

			testNS.Do(func(ns.NetNS) error {
				// Execute the "DEL" command for the plugin
				execInvokeArgs.Command = "DEL"
				err := invoke.ExecPluginWithoutResult(
					bridgePluginPath,
					[]byte(fmt.Sprintf(netConf, bridgeName, dst)),
					execInvokeArgs)
				require.NoError(t, err, "Unable to execute DEL command for ecs-bridge plugin")

				// Validate veth interface is removed
				validateLinkDoesNotExist(t, vethTestNetNS.Attrs().Name)
				// Validate that the bridge address remains unaltered
				bridge := getBridgeLink(t)
				validateBridgeAddress(t, bridge)
				return nil
			})

			targetNS.Do(func(ns.NetNS) error {
				validateLinkDoesNotExist(t, vethTargetNetNS.Attrs().Name)
				return nil
			})
		})
	}

}

// TestAddDelIPv6 tests the ADD and DEL commands with IPv6-only configuration
func TestAddDelIPv6(t *testing.T) {
	// Skip if instance doesn't support IPv6
	skipIfNoIPv6(t)

	testCases := map[string]configureNetNSFunc{
		"When Bridge Does Not Exist": configureNetNSNop,
	}

	// Ensure that the bridge plugin exists
	bridgePluginPath, err := invoke.FindInPath("ecs-bridge", []string{os.Getenv("CNI_PATH")})
	require.NoError(t, err, "Unable to find bridge plugin in path")

	// Create a directory for storing test logs
	testLogDir, err := ioutil.TempDir("", "ecs-bridge-e2e-test-ipv6-")
	require.NoError(t, err, "Unable to create directory for storing test logs")

	// Configure the env var to use the test logs directory
	os.Setenv("ECS_CNI_LOG_FILE", fmt.Sprintf("%s/bridge.log", testLogDir))
	t.Logf("Using %s for test logs", testLogDir)
	defer os.Unsetenv("ECS_CNI_LOG_FILE")

	// Handle deletion of test logs at the end of the test execution if specified
	ok, err := strconv.ParseBool(getEnvOrDefault("ECS_PRESERVE_E2E_TEST_LOGS", "false"))
	assert.NoError(t, err, "Unable to parse ECS_PRESERVE_E2E_TEST_LOGS env var")
	defer func(preserve bool) {
		if !t.Failed() && !preserve {
			os.RemoveAll(testLogDir)
		}
	}(ok)

	// Execute test cases
	for tcName, configFunc := range testCases {
		t.Run(tcName, func(t *testing.T) {
			// Create a network namespace to execute the test in
			testNS, err := ns.NewNS()
			require.NoError(t, err, "Unable to create the network namespace to run the test in")
			defer testNS.Close()

			// Create a network namespace to mimic the container's network namespace
			targetNS, err := ns.NewNS()
			require.NoError(t, err,
				"Unable to create the network namespace that represents the network namespace of the container")
			defer targetNS.Close()

			// Create a directory to store IPAM db
			ipamDir, err := ioutil.TempDir("", "ecs-ipam-ipv6-")
			require.NoError(t, err, "Unable to create a temp directory for the ipam db")
			os.Setenv("IPAM_DB_PATH", fmt.Sprintf("%s/ipam.db", ipamDir))
			defer os.Unsetenv("IPAM_DB_PATH")
			ok, err := strconv.ParseBool(getEnvOrDefault("ECS_BRIDGE_PRESERVE_IPAM_DB", "false"))
			assert.NoError(t, err, "Unable to parse ECS_BRIDGE_PRESERVE_IPAM_DB env var")
			if !ok {
				defer os.RemoveAll(ipamDir)
			}

			// Construct args to invoke the CNI plugin with
			execInvokeArgs := &invoke.Args{
				ContainerID: containerID,
				NetNS:       targetNS.Path(),
				IfName:      ifName,
				Path:        os.Getenv("CNI_PATH"),
			}

			var vethTestNetNS netlink.Link
			testNS.Do(func(ns.NetNS) error {
				err = configFunc()
				require.NoError(t, err, "Unable to configure test netns before executing ADD")

				// Execute the "ADD" command for the plugin with IPv6 config
				execInvokeArgs.Command = "ADD"
				_, err := invoke.ExecPluginWithResult(
					bridgePluginPath,
					[]byte(fmt.Sprintf(netConfIPv6, bridgeName, dstIPv6)),
					execInvokeArgs)
				require.NoError(t, err, "Unable to execute ADD command for ecs-bridge plugin with IPv6")

				// Validate that bridge was created with the expected IPv6 address
				bridge := getBridgeLink(t)
				validateBridgeAddressIPv6(t, bridge)
				// Validate that veth pair device was created
				vethTestNetNS, ok = getVethAndVerifyLo(t)
				require.True(t, ok, "veth device not found in test netns")
				return nil
			})

			var vethTargetNetNS netlink.Link
			targetNS.Do(func(ns.NetNS) error {
				// Validate the other end of the veth pair device has the desired
				// route and the address allocated to it
				vethTargetNetNS, ok = getVethAndVerifyLo(t)
				require.True(t, ok, "veth device not found in target netns")
				validateVethAddressIPv6(t, vethTargetNetNS)
				validateRouteForVethInTargetNetNSIPv6(t, vethTargetNetNS)
				return nil
			})

			testNS.Do(func(ns.NetNS) error {
				// Execute the "DEL" command for the plugin
				execInvokeArgs.Command = "DEL"
				err := invoke.ExecPluginWithoutResult(
					bridgePluginPath,
					[]byte(fmt.Sprintf(netConfIPv6, bridgeName, dstIPv6)),
					execInvokeArgs)
				require.NoError(t, err, "Unable to execute DEL command for ecs-bridge plugin")

				// Validate veth interface is removed
				validateLinkDoesNotExist(t, vethTestNetNS.Attrs().Name)
				// Validate that the bridge address remains unaltered
				bridge := getBridgeLink(t)
				validateBridgeAddressIPv6(t, bridge)
				return nil
			})

			targetNS.Do(func(ns.NetNS) error {
				validateLinkDoesNotExist(t, vethTargetNetNS.Attrs().Name)
				return nil
			})
		})
	}
}

// TestAddDelDualStack tests the ADD and DEL commands with dual-stack configuration
func TestAddDelDualStack(t *testing.T) {
	// Skip if instance doesn't support both IPv4 and IPv6
	skipIfNoDualStack(t)

	testCases := map[string]configureNetNSFunc{
		"When Bridge Does Not Exist": configureNetNSNop,
	}

	// Ensure that the bridge plugin exists
	bridgePluginPath, err := invoke.FindInPath("ecs-bridge", []string{os.Getenv("CNI_PATH")})
	require.NoError(t, err, "Unable to find bridge plugin in path")

	// Create a directory for storing test logs
	testLogDir, err := ioutil.TempDir("", "ecs-bridge-e2e-test-dualstack-")
	require.NoError(t, err, "Unable to create directory for storing test logs")

	// Configure the env var to use the test logs directory
	os.Setenv("ECS_CNI_LOG_FILE", fmt.Sprintf("%s/bridge.log", testLogDir))
	t.Logf("Using %s for test logs", testLogDir)
	defer os.Unsetenv("ECS_CNI_LOG_FILE")

	// Handle deletion of test logs at the end of the test execution if specified
	ok, err := strconv.ParseBool(getEnvOrDefault("ECS_PRESERVE_E2E_TEST_LOGS", "false"))
	assert.NoError(t, err, "Unable to parse ECS_PRESERVE_E2E_TEST_LOGS env var")
	defer func(preserve bool) {
		if !t.Failed() && !preserve {
			os.RemoveAll(testLogDir)
		}
	}(ok)

	// Execute test cases
	for tcName, configFunc := range testCases {
		t.Run(tcName, func(t *testing.T) {
			// Create a network namespace to execute the test in
			testNS, err := ns.NewNS()
			require.NoError(t, err, "Unable to create the network namespace to run the test in")
			defer testNS.Close()

			// Create a network namespace to mimic the container's network namespace
			targetNS, err := ns.NewNS()
			require.NoError(t, err,
				"Unable to create the network namespace that represents the network namespace of the container")
			defer targetNS.Close()

			// Create a directory to store IPAM db
			ipamDir, err := ioutil.TempDir("", "ecs-ipam-dualstack-")
			require.NoError(t, err, "Unable to create a temp directory for the ipam db")
			os.Setenv("IPAM_DB_PATH", fmt.Sprintf("%s/ipam.db", ipamDir))
			defer os.Unsetenv("IPAM_DB_PATH")
			ok, err := strconv.ParseBool(getEnvOrDefault("ECS_BRIDGE_PRESERVE_IPAM_DB", "false"))
			assert.NoError(t, err, "Unable to parse ECS_BRIDGE_PRESERVE_IPAM_DB env var")
			if !ok {
				defer os.RemoveAll(ipamDir)
			}

			// Construct args to invoke the CNI plugin with
			execInvokeArgs := &invoke.Args{
				ContainerID: containerID,
				NetNS:       targetNS.Path(),
				IfName:      ifName,
				Path:        os.Getenv("CNI_PATH"),
			}

			var vethTestNetNS netlink.Link
			testNS.Do(func(ns.NetNS) error {
				err = configFunc()
				require.NoError(t, err, "Unable to configure test netns before executing ADD")

				// Execute the "ADD" command for the plugin with dual-stack config
				execInvokeArgs.Command = "ADD"
				_, err := invoke.ExecPluginWithResult(
					bridgePluginPath,
					[]byte(fmt.Sprintf(netConfDualStack, bridgeName)),
					execInvokeArgs)
				require.NoError(t, err, "Unable to execute ADD command for ecs-bridge plugin with dual-stack")

				// Validate that bridge was created with both IPv4 and IPv6 addresses
				bridge := getBridgeLink(t)
				validateBridgeAddress(t, bridge)
				validateBridgeAddressIPv6(t, bridge)
				// Validate that veth pair device was created
				vethTestNetNS, ok = getVethAndVerifyLo(t)
				require.True(t, ok, "veth device not found in test netns")
				return nil
			})

			var vethTargetNetNS netlink.Link
			targetNS.Do(func(ns.NetNS) error {
				// Validate the other end of the veth pair device has the desired
				// routes and addresses for both families
				vethTargetNetNS, ok = getVethAndVerifyLo(t)
				require.True(t, ok, "veth device not found in target netns")
				validateVethAddress(t, vethTargetNetNS)
				validateVethAddressIPv6(t, vethTargetNetNS)
				validateRouteForVethInTargetNetNS(t, vethTargetNetNS)
				validateRouteForVethInTargetNetNSIPv6(t, vethTargetNetNS)
				return nil
			})

			testNS.Do(func(ns.NetNS) error {
				// Execute the "DEL" command for the plugin
				execInvokeArgs.Command = "DEL"
				err := invoke.ExecPluginWithoutResult(
					bridgePluginPath,
					[]byte(fmt.Sprintf(netConfDualStack, bridgeName)),
					execInvokeArgs)
				require.NoError(t, err, "Unable to execute DEL command for ecs-bridge plugin")

				// Validate veth interface is removed
				validateLinkDoesNotExist(t, vethTestNetNS.Attrs().Name)
				// Validate that the bridge addresses remain unaltered
				bridge := getBridgeLink(t)
				validateBridgeAddress(t, bridge)
				validateBridgeAddressIPv6(t, bridge)
				return nil
			})

			targetNS.Do(func(ns.NetNS) error {
				validateLinkDoesNotExist(t, vethTargetNetNS.Attrs().Name)
				return nil
			})
		})
	}
}

// TestAddDelECSDualStack tests the ADD and DEL commands with ECS-style dual-stack configuration:
// IPv4 link-local subnet for credentials endpoint + IPv6 default gateway for internet access
func TestAddDelECSDualStack(t *testing.T) {
	// Skip if instance doesn't support both IPv4 and IPv6
	skipIfNoDualStack(t)

	testCases := map[string]configureNetNSFunc{
		"When Bridge Does Not Exist": configureNetNSNop,
	}

	// Ensure that the bridge plugin exists
	bridgePluginPath, err := invoke.FindInPath("ecs-bridge", []string{os.Getenv("CNI_PATH")})
	require.NoError(t, err, "Unable to find bridge plugin in path")

	// Create a directory for storing test logs
	testLogDir, err := ioutil.TempDir("", "ecs-bridge-e2e-test-ecs-dualstack-")
	require.NoError(t, err, "Unable to create directory for storing test logs")

	// Configure the env var to use the test logs directory
	os.Setenv("ECS_CNI_LOG_FILE", fmt.Sprintf("%s/bridge.log", testLogDir))
	t.Logf("Using %s for test logs", testLogDir)
	defer os.Unsetenv("ECS_CNI_LOG_FILE")

	// Handle deletion of test logs at the end of the test execution if specified
	ok, err := strconv.ParseBool(getEnvOrDefault("ECS_PRESERVE_E2E_TEST_LOGS", "false"))
	assert.NoError(t, err, "Unable to parse ECS_PRESERVE_E2E_TEST_LOGS env var")
	defer func(preserve bool) {
		if !t.Failed() && !preserve {
			os.RemoveAll(testLogDir)
		}
	}(ok)

	// Execute test cases
	for tcName, configFunc := range testCases {
		t.Run(tcName, func(t *testing.T) {
			// Create a network namespace to execute the test in
			testNS, err := ns.NewNS()
			require.NoError(t, err, "Unable to create the network namespace to run the test in")
			defer testNS.Close()

			// Create a network namespace to mimic the container's network namespace
			targetNS, err := ns.NewNS()
			require.NoError(t, err,
				"Unable to create the network namespace that represents the network namespace of the container")
			defer targetNS.Close()

			// Create a directory to store IPAM db
			ipamDir, err := ioutil.TempDir("", "ecs-ipam-ecs-dualstack-")
			require.NoError(t, err, "Unable to create a temp directory for the ipam db")
			os.Setenv("IPAM_DB_PATH", fmt.Sprintf("%s/ipam.db", ipamDir))
			defer os.Unsetenv("IPAM_DB_PATH")
			ok, err := strconv.ParseBool(getEnvOrDefault("ECS_BRIDGE_PRESERVE_IPAM_DB", "false"))
			assert.NoError(t, err, "Unable to parse ECS_BRIDGE_PRESERVE_IPAM_DB env var")
			if !ok {
				defer os.RemoveAll(ipamDir)
			}

			// Construct args to invoke the CNI plugin with
			execInvokeArgs := &invoke.Args{
				ContainerID: containerID,
				NetNS:       targetNS.Path(),
				IfName:      ifName,
				Path:        os.Getenv("CNI_PATH"),
			}

			var vethTestNetNS netlink.Link
			testNS.Do(func(ns.NetNS) error {
				err = configFunc()
				require.NoError(t, err, "Unable to configure test netns before executing ADD")

				// Execute the "ADD" command for the plugin with ECS dual-stack config
				execInvokeArgs.Command = "ADD"
				_, err := invoke.ExecPluginWithResult(
					bridgePluginPath,
					[]byte(fmt.Sprintf(netConfECSDualStack, bridgeName)),
					execInvokeArgs)
				require.NoError(t, err, "Unable to execute ADD command for ecs-bridge plugin with ECS dual-stack")

				// Validate that bridge was created with both IPv4 link-local and IPv6 addresses
				bridge := getBridgeLink(t)
				validateBridgeAddress(t, bridge)
				validateBridgeAddressIPv6(t, bridge)
				// Validate that veth pair device was created
				vethTestNetNS, ok = getVethAndVerifyLo(t)
				require.True(t, ok, "veth device not found in test netns")
				return nil
			})

			var vethTargetNetNS netlink.Link
			targetNS.Do(func(ns.NetNS) error {
				// Validate the other end of the veth pair device has the desired
				// routes and addresses for both families
				vethTargetNetNS, ok = getVethAndVerifyLo(t)
				require.True(t, ok, "veth device not found in target netns")
				// Validate IPv4 link-local address for credentials endpoint
				validateVethAddress(t, vethTargetNetNS)
				// Validate IPv6 address
				validateVethAddressIPv6(t, vethTargetNetNS)
				// Validate IPv4 route to credentials endpoint
				validateRouteForVethInTargetNetNS(t, vethTargetNetNS)
				// Validate IPv6 default gateway route
				validateIPv6DefaultGatewayRoute(t, vethTargetNetNS)
				return nil
			})

			testNS.Do(func(ns.NetNS) error {
				// Execute the "DEL" command for the plugin
				execInvokeArgs.Command = "DEL"
				err := invoke.ExecPluginWithoutResult(
					bridgePluginPath,
					[]byte(fmt.Sprintf(netConfECSDualStack, bridgeName)),
					execInvokeArgs)
				require.NoError(t, err, "Unable to execute DEL command for ecs-bridge plugin")

				// Validate veth interface is removed
				validateLinkDoesNotExist(t, vethTestNetNS.Attrs().Name)
				// Validate that the bridge addresses remain unaltered
				bridge := getBridgeLink(t)
				validateBridgeAddress(t, bridge)
				validateBridgeAddressIPv6(t, bridge)
				return nil
			})

			targetNS.Do(func(ns.NetNS) error {
				validateLinkDoesNotExist(t, vethTargetNetNS.Attrs().Name)
				return nil
			})
		})
	}
}

// configureNetNSWithBridge creates a bridge in the network namespace
func configureNetNSWithBridge() error {
	bridgeLinkAttributes := netlink.NewLinkAttrs()
	bridgeLinkAttributes.Name = bridgeName

	return netlink.LinkAdd(&netlink.Bridge{
		LinkAttrs: bridgeLinkAttributes,
	})
}

// configureNetNSWithBridgeAndSetIPAddress creates a bridge in the network namespace
// and sets and IP address for the same
func configureNetNSWithBridgeAndSetIPAddress() error {
	if err := configureNetNSWithBridge(); err != nil {
		return err
	}

	bridge, err := netlink.LinkByName(bridgeName)
	if err != nil {
		return err
	}

	ip, ipNetAddr, err := net.ParseCIDR(expectedBridgeAddress)
	if err != nil {
		return err
	}
	return netlink.AddrAdd(bridge, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: ipNetAddr.Mask,
		},
	})
}

func configureNetNSNop() error {
	return nil
}

// getEnvOrDefault gets the value of an env var. It returns the fallback value
// if the env var is not set
func getEnvOrDefault(name string, fallback string) string {
	val := os.Getenv(name)
	if val == "" {
		return fallback
	}

	return val
}

// getBridgeLink gets a handle to the bridge device
func getBridgeLink(t *testing.T) netlink.Link {
	bridgeLink, err := netlink.LinkByName(bridgeName)
	require.NoError(t, err, "Unable to find bridge: %s", bridgeName)
	_, ok := bridgeLink.(*netlink.Bridge)
	require.True(t, ok, "Link named '%s' is not a bridge", bridgeName)
	return bridgeLink
}

// validateBridgeAddress validates that the bridge is set up with the expected
// IP address
func validateBridgeAddress(t *testing.T, bridge netlink.Link) {
	addrs, err := netlink.AddrList(bridge, netlink.FAMILY_V4)
	require.NoError(t, err, "Unable to list the addresses of: %s", bridge.Attrs().Name)
	addressFound := false
	for _, addr := range addrs {
		if addr.IPNet.String() == expectedBridgeAddress {
			addressFound = true
		}
	}
	require.True(t, addressFound, "IP address '%s' not assigned to bridge: %s",
		expectedBridgeAddress, bridge.Attrs().Name)
}

// getVethAndVerifyLo gets the veth pair device in the namespace. It also
// verifies that localhost interface device exists in the namespace
func getVethAndVerifyLo(t *testing.T) (netlink.Link, bool) {
	links, err := netlink.LinkList()
	require.NoError(t, err, "Unable to list devices")
	loFound := false
	vethFound := false
	var veth netlink.Link
	for _, link := range links {
		switch link.Type() {
		case "device":
			if link.Attrs().Name == "lo" {
				loFound = true
			}
		case "veth":
			vethFound = true
			veth = link
		}
	}

	require.True(t, loFound, "localhost interface not found in netns")
	return veth, vethFound
}

// validateVethAddress validates the address of the veth device
func validateVethAddress(t *testing.T, veth netlink.Link) {
	addrs, err := netlink.AddrList(veth, netlink.FAMILY_V4)
	require.NoError(t, err, "Unable to list addresses of: %s", veth.Attrs().Name)
	addressFound := false
	for _, addr := range addrs {
		if addr.IPNet.String() == expectedVethAddress {
			addressFound = true
		}
	}
	require.True(t, addressFound, "IP address '%s' not associated with: %s",
		expectedVethAddress, veth.Attrs().Name)
}

// validateRouteForVethInTargetNetNS validates that the expected route has been
// added for the veth device in target network namespace
func validateRouteForVethInTargetNetNS(t *testing.T, veth netlink.Link) {
	routes, err := netlink.RouteList(veth, netlink.FAMILY_V4)
	require.NoError(t, err, "Unable to list routes for: %s", veth.Attrs().Name)
	gwRouteFound := false
	routeFound := false
	defaultRouteFound := false
	for _, route := range routes {
		if route.Gw == nil {
			defaultRouteFound = true
		} else if route.Dst.String() == dst &&
			route.Src == nil &&
			route.Gw.String() == expectedGateway {
			routeFound = true
		} else if route.Dst.String() == bridgeDst && route.Gw.String() == expectedGateway {
			gwRouteFound = true
		}
	}
	require.False(t, defaultRouteFound,
		"Unexpected default route found for: %s", veth.Attrs().Name)
	require.True(t, routeFound, "Route with gateway '%s' not found for: %s",
		expectedGateway, veth.Attrs().Name)
	require.True(t, gwRouteFound,
		"route for the gateway is not found")
}

// validateLinkDoesNotExist validates that the named link does not exist in the
// network namespace
func validateLinkDoesNotExist(t *testing.T, name string) {
	_, err := netlink.LinkByName(name)
	require.Error(t, err, "Link %s should not exist", name)
	_, ok := err.(netlink.LinkNotFoundError)
	require.True(t, ok, "Error type is incorrect for link '%s': %v", name, err)
}

// validateBridgeAddressIPv6 validates that the bridge is set up with the expected
// IPv6 address
func validateBridgeAddressIPv6(t *testing.T, bridge netlink.Link) {
	addrs, err := netlink.AddrList(bridge, netlink.FAMILY_V6)
	require.NoError(t, err, "Unable to list the IPv6 addresses of: %s", bridge.Attrs().Name)
	addressFound := false
	for _, addr := range addrs {
		if addr.IPNet.String() == expectedBridgeAddressIPv6 {
			addressFound = true
		}
	}
	require.True(t, addressFound, "IPv6 address '%s' not assigned to bridge: %s",
		expectedBridgeAddressIPv6, bridge.Attrs().Name)
}

// validateVethAddressIPv6 validates the IPv6 address of the veth device
func validateVethAddressIPv6(t *testing.T, veth netlink.Link) {
	addrs, err := netlink.AddrList(veth, netlink.FAMILY_V6)
	require.NoError(t, err, "Unable to list IPv6 addresses of: %s", veth.Attrs().Name)
	addressFound := false
	for _, addr := range addrs {
		if addr.IPNet.String() == expectedVethAddressIPv6 {
			addressFound = true
		}
	}
	require.True(t, addressFound, "IPv6 address '%s' not associated with: %s",
		expectedVethAddressIPv6, veth.Attrs().Name)
}

// validateRouteForVethInTargetNetNSIPv6 validates that the expected IPv6 route has been
// added for the veth device in target network namespace
func validateRouteForVethInTargetNetNSIPv6(t *testing.T, veth netlink.Link) {
	routes, err := netlink.RouteList(veth, netlink.FAMILY_V6)
	require.NoError(t, err, "Unable to list IPv6 routes for: %s", veth.Attrs().Name)
	gwRouteFound := false
	routeFound := false
	defaultRouteFound := false
	for _, route := range routes {
		if route.Gw == nil && route.Dst != nil && route.Dst.IP.IsGlobalUnicast() {
			// Skip link-local routes, only check for default routes
			if route.Dst.String() == "::/0" {
				defaultRouteFound = true
			}
		} else if route.Dst != nil && route.Dst.String() == dstIPv6 &&
			route.Src == nil &&
			route.Gw != nil && route.Gw.String() == expectedGatewayIPv6 {
			routeFound = true
		} else if route.Dst != nil && route.Dst.String() == bridgeDstIPv6 &&
			route.Gw != nil && route.Gw.String() == expectedGatewayIPv6 {
			gwRouteFound = true
		}
	}
	require.False(t, defaultRouteFound,
		"Unexpected default IPv6 route found for: %s", veth.Attrs().Name)
	require.True(t, routeFound, "IPv6 route with gateway '%s' not found for: %s",
		expectedGatewayIPv6, veth.Attrs().Name)
	require.True(t, gwRouteFound,
		"IPv6 route for the gateway is not found")
}

// validateIPv6DefaultGatewayRoute validates that the IPv6 default gateway route (::/0)
// has been added for the veth device in target network namespace
func validateIPv6DefaultGatewayRoute(t *testing.T, veth netlink.Link) {
	routes, err := netlink.RouteList(veth, netlink.FAMILY_V6)
	require.NoError(t, err, "Unable to list IPv6 routes for: %s", veth.Attrs().Name)
	defaultRouteFound := false
	gwRouteFound := false
	for _, route := range routes {
		// Check for default route (::/0) with gateway
		// The kernel stores default routes with Dst=nil, so we check for that
		isDefaultRoute := route.Dst == nil || (route.Dst != nil && route.Dst.String() == "::/0")
		if isDefaultRoute && route.Gw != nil && route.Gw.String() == expectedGatewayIPv6 {
			defaultRouteFound = true
		}
		// Check for gateway route (2001:db8::1/128)
		if route.Dst != nil && route.Dst.String() == bridgeDstIPv6 &&
			route.Gw != nil && route.Gw.String() == expectedGatewayIPv6 {
			gwRouteFound = true
		}
	}
	require.True(t, defaultRouteFound,
		"IPv6 default route (::/0) with gateway '%s' not found for: %s",
		expectedGatewayIPv6, veth.Attrs().Name)
	require.True(t, gwRouteFound,
		"IPv6 gateway route (%s) not found for: %s", bridgeDstIPv6, veth.Attrs().Name)
}

// ============================================================================
// Host Interface Tests - Tests using the host's primary interface (eth0)
// These tests create a bridge connected to the host's primary interface
// without creating new ENIs
// ============================================================================

const (
	hostBridgeName = "ecs-host-bridge"
	hostIfName     = "ecs-host-eth0"

	// Configuration for host interface test with IPv4 link-local
	// Uses the host's primary interface and adds a route to the link-local subnet
	netConfHostIPv4 = `
{
    "type":"ecs-bridge",
    "cniVersion":"0.3.0",
    "bridge":"%s",
    "ipam":{
	"type":"ecs-ipam",
	"id":"test-host-ipv4",
	"cniVersion":"0.3.0",
	"ipv4-subnet":"169.254.172.0/22",
	"ipv4-routes":[
	    {
		"dst":"169.254.170.2/32"
	    }
	]
    }
}`

	// Configuration for host interface test with IPv6
	// Uses the host's primary interface with IPv6 addressing
	netConfHostIPv6 = `
{
    "type":"ecs-bridge",
    "cniVersion":"0.3.0",
    "bridge":"%s",
    "ipam":{
	"type":"ecs-ipam",
	"id":"test-host-ipv6",
	"cniVersion":"0.3.0",
	"ipv6-subnet":"2001:db8::/64",
	"ipv6-routes":[
	    {
		"dst":"fd00:ec2::254/128"
	    }
	]
    }
}`
)

// getPrimaryInterface returns the name of the primary network interface (typically eth0 or ens5)
func getPrimaryInterface() (string, error) {
	// Try common interface names in order of preference
	commonNames := []string{"eth0", "ens5", "ens3", "enp0s3"}
	for _, name := range commonNames {
		if _, err := netlink.LinkByName(name); err == nil {
			return name, nil
		}
	}

	// Fall back to finding the first non-loopback interface with an IP address
	links, err := netlink.LinkList()
	if err != nil {
		return "", err
	}

	for _, link := range links {
		if link.Attrs().Name == "lo" {
			continue
		}
		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			continue
		}
		if len(addrs) > 0 {
			return link.Attrs().Name, nil
		}
	}

	return "", fmt.Errorf("no suitable primary interface found")
}

// getHostInterfaceIPv4 returns the IPv4 address of the host's primary interface
func getHostInterfaceIPv4(ifaceName string) (net.IP, error) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, err
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if addr.IP.To4() != nil && !addr.IP.IsLinkLocalUnicast() {
			return addr.IP, nil
		}
	}

	return nil, fmt.Errorf("no IPv4 address found on interface %s", ifaceName)
}

// getHostInterfaceIPv6 returns the IPv6 address of the host's primary interface
func getHostInterfaceIPv6(ifaceName string) (net.IP, error) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, err
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if addr.IP.To4() == nil && !addr.IP.IsLinkLocalUnicast() {
			return addr.IP, nil
		}
	}

	return nil, fmt.Errorf("no IPv6 address found on interface %s", ifaceName)
}

// TestHostInterfaceIPv4 tests the bridge plugin using the host's primary interface
// with IPv4 link-local addressing (169.254.172.0/22) for ECS credentials endpoint access.
// This test does NOT create a new ENI - it uses the existing host interface.
func TestHostInterfaceIPv4(t *testing.T) {
	// Skip if instance doesn't support IPv4
	skipIfNoIPv4(t)

	// Get the primary interface name
	primaryIface, err := getPrimaryInterface()
	require.NoError(t, err, "Unable to find primary interface")
	t.Logf("Using primary interface: %s", primaryIface)

	// Verify the interface has an IPv4 address
	hostIP, err := getHostInterfaceIPv4(primaryIface)
	require.NoError(t, err, "Primary interface %s does not have an IPv4 address", primaryIface)
	t.Logf("Host IPv4 address: %s", hostIP)

	// Ensure that the bridge plugin exists
	bridgePluginPath, err := invoke.FindInPath("ecs-bridge", []string{os.Getenv("CNI_PATH")})
	require.NoError(t, err, "Unable to find bridge plugin in path")

	// Create a directory for storing test logs
	testLogDir, err := ioutil.TempDir("", "ecs-bridge-e2e-host-ipv4-")
	require.NoError(t, err, "Unable to create directory for storing test logs")

	os.Setenv("ECS_CNI_LOG_FILE", fmt.Sprintf("%s/bridge.log", testLogDir))
	t.Logf("Using %s for test logs", testLogDir)
	defer os.Unsetenv("ECS_CNI_LOG_FILE")

	ok, err := strconv.ParseBool(getEnvOrDefault("ECS_PRESERVE_E2E_TEST_LOGS", "false"))
	assert.NoError(t, err, "Unable to parse ECS_PRESERVE_E2E_TEST_LOGS env var")
	defer func(preserve bool) {
		if !t.Failed() && !preserve {
			os.RemoveAll(testLogDir)
		}
	}(ok)

	// Create a network namespace for the bridge (simulating the host namespace)
	testNS, err := ns.NewNS()
	require.NoError(t, err, "Unable to create the network namespace to run the test in")
	defer testNS.Close()

	// Create a network namespace to mimic the container's network namespace
	targetNS, err := ns.NewNS()
	require.NoError(t, err, "Unable to create the container network namespace")
	defer targetNS.Close()

	// Create a directory to store IPAM db
	ipamDir, err := ioutil.TempDir("", "ecs-ipam-host-ipv4-")
	require.NoError(t, err, "Unable to create a temp directory for the ipam db")
	os.Setenv("IPAM_DB_PATH", fmt.Sprintf("%s/ipam.db", ipamDir))
	defer os.Unsetenv("IPAM_DB_PATH")
	ok, err = strconv.ParseBool(getEnvOrDefault("ECS_BRIDGE_PRESERVE_IPAM_DB", "false"))
	assert.NoError(t, err, "Unable to parse ECS_BRIDGE_PRESERVE_IPAM_DB env var")
	if !ok {
		defer os.RemoveAll(ipamDir)
	}

	// Construct args to invoke the CNI plugin with
	execInvokeArgs := &invoke.Args{
		ContainerID: containerID,
		NetNS:       targetNS.Path(),
		IfName:      hostIfName,
		Path:        os.Getenv("CNI_PATH"),
	}

	var vethTestNetNS netlink.Link
	testNS.Do(func(ns.NetNS) error {
		// Execute the "ADD" command for the plugin
		execInvokeArgs.Command = "ADD"
		_, err := invoke.ExecPluginWithResult(
			bridgePluginPath,
			[]byte(fmt.Sprintf(netConfHostIPv4, hostBridgeName)),
			execInvokeArgs)
		require.NoError(t, err, "Unable to execute ADD command for ecs-bridge plugin with host IPv4")

		// Validate that bridge was created with the expected IPv4 link-local address
		bridge, err := netlink.LinkByName(hostBridgeName)
		require.NoError(t, err, "Unable to find bridge: %s", hostBridgeName)
		validateBridgeAddressGeneric(t, bridge, expectedBridgeAddress, netlink.FAMILY_V4)

		// Validate that veth pair device was created
		vethTestNetNS, ok = getVethAndVerifyLo(t)
		require.True(t, ok, "veth device not found in test netns")
		return nil
	})

	var vethTargetNetNS netlink.Link
	targetNS.Do(func(ns.NetNS) error {
		// Validate the container end of the veth pair
		vethTargetNetNS, ok = getVethAndVerifyLo(t)
		require.True(t, ok, "veth device not found in target netns")
		validateVethAddress(t, vethTargetNetNS)
		validateRouteForVethInTargetNetNS(t, vethTargetNetNS)
		return nil
	})

	testNS.Do(func(ns.NetNS) error {
		// Execute the "DEL" command for the plugin
		execInvokeArgs.Command = "DEL"
		err := invoke.ExecPluginWithoutResult(
			bridgePluginPath,
			[]byte(fmt.Sprintf(netConfHostIPv4, hostBridgeName)),
			execInvokeArgs)
		require.NoError(t, err, "Unable to execute DEL command for ecs-bridge plugin")

		// Validate veth interface is removed
		validateLinkDoesNotExist(t, vethTestNetNS.Attrs().Name)
		return nil
	})

	targetNS.Do(func(ns.NetNS) error {
		validateLinkDoesNotExist(t, vethTargetNetNS.Attrs().Name)
		return nil
	})
}

// TestHostInterfaceIPv6Only tests the bridge plugin using the host's primary interface
// with IPv6-only addressing. This simulates an IPv6-only ENI scenario.
// This test does NOT create a new ENI - it uses the existing host interface.
func TestHostInterfaceIPv6Only(t *testing.T) {
	// Skip if instance doesn't support IPv6
	skipIfNoIPv6(t)

	// Get the primary interface name
	primaryIface, err := getPrimaryInterface()
	require.NoError(t, err, "Unable to find primary interface")
	t.Logf("Using primary interface: %s", primaryIface)

	// Verify the interface has an IPv6 address
	hostIP, err := getHostInterfaceIPv6(primaryIface)
	if err != nil {
		t.Skipf("Skipping test: primary interface %s does not have an IPv6 address: %v", primaryIface, err)
	}
	t.Logf("Host IPv6 address: %s", hostIP)

	// Ensure that the bridge plugin exists
	bridgePluginPath, err := invoke.FindInPath("ecs-bridge", []string{os.Getenv("CNI_PATH")})
	require.NoError(t, err, "Unable to find bridge plugin in path")

	// Create a directory for storing test logs
	testLogDir, err := ioutil.TempDir("", "ecs-bridge-e2e-host-ipv6-")
	require.NoError(t, err, "Unable to create directory for storing test logs")

	os.Setenv("ECS_CNI_LOG_FILE", fmt.Sprintf("%s/bridge.log", testLogDir))
	t.Logf("Using %s for test logs", testLogDir)
	defer os.Unsetenv("ECS_CNI_LOG_FILE")

	ok, err := strconv.ParseBool(getEnvOrDefault("ECS_PRESERVE_E2E_TEST_LOGS", "false"))
	assert.NoError(t, err, "Unable to parse ECS_PRESERVE_E2E_TEST_LOGS env var")
	defer func(preserve bool) {
		if !t.Failed() && !preserve {
			os.RemoveAll(testLogDir)
		}
	}(ok)

	// Create a network namespace for the bridge (simulating the host namespace)
	testNS, err := ns.NewNS()
	require.NoError(t, err, "Unable to create the network namespace to run the test in")
	defer testNS.Close()

	// Create a network namespace to mimic the container's network namespace
	targetNS, err := ns.NewNS()
	require.NoError(t, err, "Unable to create the container network namespace")
	defer targetNS.Close()

	// Create a directory to store IPAM db
	ipamDir, err := ioutil.TempDir("", "ecs-ipam-host-ipv6-")
	require.NoError(t, err, "Unable to create a temp directory for the ipam db")
	os.Setenv("IPAM_DB_PATH", fmt.Sprintf("%s/ipam.db", ipamDir))
	defer os.Unsetenv("IPAM_DB_PATH")
	ok, err = strconv.ParseBool(getEnvOrDefault("ECS_BRIDGE_PRESERVE_IPAM_DB", "false"))
	assert.NoError(t, err, "Unable to parse ECS_BRIDGE_PRESERVE_IPAM_DB env var")
	if !ok {
		defer os.RemoveAll(ipamDir)
	}

	// Construct args to invoke the CNI plugin with
	execInvokeArgs := &invoke.Args{
		ContainerID: containerID,
		NetNS:       targetNS.Path(),
		IfName:      hostIfName,
		Path:        os.Getenv("CNI_PATH"),
	}

	var vethTestNetNS netlink.Link
	testNS.Do(func(ns.NetNS) error {
		// Execute the "ADD" command for the plugin
		execInvokeArgs.Command = "ADD"
		_, err := invoke.ExecPluginWithResult(
			bridgePluginPath,
			[]byte(fmt.Sprintf(netConfHostIPv6, hostBridgeName)),
			execInvokeArgs)
		require.NoError(t, err, "Unable to execute ADD command for ecs-bridge plugin with host IPv6")

		// Validate that bridge was created with the expected IPv6 address
		bridge, err := netlink.LinkByName(hostBridgeName)
		require.NoError(t, err, "Unable to find bridge: %s", hostBridgeName)
		validateBridgeAddressGeneric(t, bridge, expectedBridgeAddressIPv6, netlink.FAMILY_V6)

		// Validate that veth pair device was created
		vethTestNetNS, ok = getVethAndVerifyLo(t)
		require.True(t, ok, "veth device not found in test netns")
		return nil
	})

	var vethTargetNetNS netlink.Link
	targetNS.Do(func(ns.NetNS) error {
		// Validate the container end of the veth pair
		vethTargetNetNS, ok = getVethAndVerifyLo(t)
		require.True(t, ok, "veth device not found in target netns")
		validateVethAddressIPv6(t, vethTargetNetNS)
		validateRouteForVethInTargetNetNSIPv6(t, vethTargetNetNS)
		return nil
	})

	testNS.Do(func(ns.NetNS) error {
		// Execute the "DEL" command for the plugin
		execInvokeArgs.Command = "DEL"
		err := invoke.ExecPluginWithoutResult(
			bridgePluginPath,
			[]byte(fmt.Sprintf(netConfHostIPv6, hostBridgeName)),
			execInvokeArgs)
		require.NoError(t, err, "Unable to execute DEL command for ecs-bridge plugin")

		// Validate veth interface is removed
		validateLinkDoesNotExist(t, vethTestNetNS.Attrs().Name)
		return nil
	})

	targetNS.Do(func(ns.NetNS) error {
		validateLinkDoesNotExist(t, vethTargetNetNS.Attrs().Name)
		return nil
	})
}

// validateBridgeAddressGeneric validates that the bridge has the expected address
// for the specified address family
func validateBridgeAddressGeneric(t *testing.T, bridge netlink.Link, expectedAddr string, family int) {
	addrs, err := netlink.AddrList(bridge, family)
	require.NoError(t, err, "Unable to list addresses of: %s", bridge.Attrs().Name)
	addressFound := false
	for _, addr := range addrs {
		if addr.IPNet.String() == expectedAddr {
			addressFound = true
		}
	}
	require.True(t, addressFound, "Address '%s' not assigned to bridge: %s",
		expectedAddr, bridge.Attrs().Name)
}

// ============================================================================
// Daemon Host Namespace Validation Functions
// These functions validate the network configuration for daemon host namespace tests
// ============================================================================

// validateDaemonBridgeIPv4 validates that the bridge has the expected IPv4 link-local
// address (169.254.172.1/22) for daemon host namespace connectivity.
// This validates Requirement 3.1: Bridge has expected IPv4 link-local address.
func validateDaemonBridgeIPv4(t *testing.T, bridge netlink.Link) {
	addrs, err := netlink.AddrList(bridge, netlink.FAMILY_V4)
	require.NoError(t, err, "Unable to list the IPv4 addresses of: %s", bridge.Attrs().Name)
	addressFound := false
	for _, addr := range addrs {
		if addr.IPNet.String() == expectedDaemonBridgeIPv4 {
			addressFound = true
		}
	}
	require.True(t, addressFound, "IPv4 address '%s' not assigned to daemon bridge: %s",
		expectedDaemonBridgeIPv4, bridge.Attrs().Name)
}

// validateDaemonVethIPv4 validates that the veth has an IPv4 address from the
// ECS link-local subnet (169.254.172.0/22) for daemon host namespace connectivity.
// This validates Requirement 3.2: Veth has IPv4 address from ECS_Link_Local_Subnet.
func validateDaemonVethIPv4(t *testing.T, veth netlink.Link) {
	addrs, err := netlink.AddrList(veth, netlink.FAMILY_V4)
	require.NoError(t, err, "Unable to list IPv4 addresses of: %s", veth.Attrs().Name)
	addressFound := false
	for _, addr := range addrs {
		if addr.IPNet.String() == expectedDaemonVethIPv4 {
			addressFound = true
		}
	}
	require.True(t, addressFound, "IPv4 address '%s' not associated with daemon veth: %s",
		expectedDaemonVethIPv4, veth.Attrs().Name)
}

// validateDaemonRoutesIPv4 validates IPv4 routes for daemon host namespace connectivity.
// This validates Requirement 3.3: Route to ECS_Credentials_Endpoint (169.254.170.2/32)
// exists via the bridge gateway.
// **Feature: daemon-host-ns-e2e-test, Property 1: IPv4 Link-Local Configuration Invariant**
func validateDaemonRoutesIPv4(t *testing.T, veth netlink.Link) {
	routes, err := netlink.RouteList(veth, netlink.FAMILY_V4)
	require.NoError(t, err, "Unable to list routes for: %s", veth.Attrs().Name)

	// Track which routes we find
	ecsCredentialsRouteFound := false
	gwRouteFound := false

	// Expected gateway route destination (gateway IP as /32)
	expectedGwDst := ecsLinkLocalGateway + "/32"

	for _, route := range routes {
		// Check for route to ECS credentials endpoint (169.254.170.2/32) via gateway
		if route.Dst != nil && route.Dst.String() == ecsCredentialsEndpointDst &&
			route.Gw != nil && route.Gw.String() == ecsLinkLocalGateway {
			ecsCredentialsRouteFound = true
		}
		// Check for gateway route (169.254.172.1/32) via gateway
		if route.Dst != nil && route.Dst.String() == expectedGwDst &&
			route.Gw != nil && route.Gw.String() == ecsLinkLocalGateway {
			gwRouteFound = true
		}
	}

	require.True(t, ecsCredentialsRouteFound,
		"Route to ECS credentials endpoint '%s' via gateway '%s' not found for: %s",
		ecsCredentialsEndpointDst, ecsLinkLocalGateway, veth.Attrs().Name)
	require.True(t, gwRouteFound,
		"Gateway route '%s' via gateway '%s' not found for: %s",
		expectedGwDst, ecsLinkLocalGateway, veth.Attrs().Name)
}

// validateDaemonBridgeIPv6 validates that the bridge has the expected IPv6 address
// (2001:db8:daemon::1/64) for daemon host namespace connectivity.
// This validates Requirement 4.1: Bridge has expected IPv6 address.
// **Feature: daemon-host-ns-e2e-test, Property 2: IPv6 Configuration Invariant**
func validateDaemonBridgeIPv6(t *testing.T, bridge netlink.Link) {
	addrs, err := netlink.AddrList(bridge, netlink.FAMILY_V6)
	require.NoError(t, err, "Unable to list the IPv6 addresses of: %s", bridge.Attrs().Name)
	addressFound := false
	for _, addr := range addrs {
		if addr.IPNet.String() == expectedDaemonBridgeIPv6 {
			addressFound = true
		}
	}
	require.True(t, addressFound, "IPv6 address '%s' not assigned to daemon bridge: %s",
		expectedDaemonBridgeIPv6, bridge.Attrs().Name)
}

// validateDaemonVethIPv6 validates that the veth has an IPv6 address
// (2001:db8:daemon::2/64) for daemon host namespace connectivity.
// This validates Requirement 4.2: Veth has IPv6 address.
// **Feature: daemon-host-ns-e2e-test, Property 2: IPv6 Configuration Invariant**
func validateDaemonVethIPv6(t *testing.T, veth netlink.Link) {
	addrs, err := netlink.AddrList(veth, netlink.FAMILY_V6)
	require.NoError(t, err, "Unable to list IPv6 addresses of: %s", veth.Attrs().Name)
	addressFound := false
	for _, addr := range addrs {
		if addr.IPNet.String() == expectedDaemonVethIPv6 {
			addressFound = true
		}
	}
	require.True(t, addressFound, "IPv6 address '%s' not associated with daemon veth: %s",
		expectedDaemonVethIPv6, veth.Attrs().Name)
}

// validateDaemonRoutesIPv6 validates IPv6 default route for external traffic
// in daemon host namespace connectivity.
// This validates Requirements 4.3, 4.4: IPv6 default route (::/0) exists with correct gateway.
// **Feature: daemon-host-ns-e2e-test, Property 2: IPv6 Configuration Invariant**
func validateDaemonRoutesIPv6(t *testing.T, veth netlink.Link) {
	routes, err := netlink.RouteList(veth, netlink.FAMILY_V6)
	require.NoError(t, err, "Unable to list IPv6 routes for: %s", veth.Attrs().Name)

	// Track which routes we find
	defaultRouteFound := false
	gwRouteFound := false

	// Expected gateway route destination (gateway IP as /128)
	expectedGwDst := daemonIPv6Gateway + "/128"

	for _, route := range routes {
		// Check for default route (::/0) with gateway
		// The kernel stores default routes with Dst=nil, so we check for that
		isDefaultRoute := route.Dst == nil || (route.Dst != nil && route.Dst.String() == "::/0")
		if isDefaultRoute && route.Gw != nil && route.Gw.String() == daemonIPv6Gateway {
			defaultRouteFound = true
		}
		// Check for gateway route (2001:db8:daemon::1/128)
		if route.Dst != nil && route.Dst.String() == expectedGwDst &&
			route.Gw != nil && route.Gw.String() == daemonIPv6Gateway {
			gwRouteFound = true
		}
	}

	require.True(t, defaultRouteFound,
		"IPv6 default route (::/0) with gateway '%s' not found for: %s",
		daemonIPv6Gateway, veth.Attrs().Name)
	require.True(t, gwRouteFound,
		"IPv6 gateway route (%s) not found for: %s", expectedGwDst, veth.Attrs().Name)
}

// ============================================================================
// Diagnostic Logging Functions
// ============================================================================

// logNetworkState logs the current network configuration for debugging.
// This function provides detailed diagnostic information when failures occur,
// helping to identify the root cause of IPv6 bugs.
// This validates Requirements 8.1, 8.2, 8.3: Log interfaces, addresses, routes, and states.
func logNetworkState(t *testing.T, targetNS ns.NetNS, description string) {
	targetNS.Do(func(ns.NetNS) error {
		t.Logf("=== Network State: %s ===", description)

		// Log all interfaces with their addresses (IPv4 and IPv6)
		links, err := netlink.LinkList()
		if err != nil {
			t.Logf("Error listing interfaces: %v", err)
			return nil
		}

		for _, link := range links {
			// Log interface states and types
			t.Logf("Interface: %s (type: %s, state: %s)",
				link.Attrs().Name, link.Type(), link.Attrs().OperState)

			// Log IPv4 addresses
			addrsV4, err := netlink.AddrList(link, netlink.FAMILY_V4)
			if err != nil {
				t.Logf("  Error listing IPv4 addresses: %v", err)
			} else {
				for _, addr := range addrsV4 {
					t.Logf("  IPv4: %s", addr.IPNet.String())
				}
			}

			// Log IPv6 addresses
			addrsV6, err := netlink.AddrList(link, netlink.FAMILY_V6)
			if err != nil {
				t.Logf("  Error listing IPv6 addresses: %v", err)
			} else {
				for _, addr := range addrsV6 {
					t.Logf("  IPv6: %s", addr.IPNet.String())
				}
			}
		}

		// Log IPv4 routes
		routesV4, err := netlink.RouteList(nil, netlink.FAMILY_V4)
		if err != nil {
			t.Logf("Error listing IPv4 routes: %v", err)
		} else {
			t.Logf("IPv4 Routes:")
			for _, route := range routesV4 {
				t.Logf("  dst=%v gw=%v", route.Dst, route.Gw)
			}
		}

		// Log IPv6 routes
		routesV6, err := netlink.RouteList(nil, netlink.FAMILY_V6)
		if err != nil {
			t.Logf("Error listing IPv6 routes: %v", err)
		} else {
			t.Logf("IPv6 Routes:")
			for _, route := range routesV6 {
				t.Logf("  dst=%v gw=%v", route.Dst, route.Gw)
			}
		}

		return nil
	})
}

// ============================================================================
// Daemon Host Namespace Test
// This test validates daemon host namespace connectivity with IPv4 link-local
// for ECS credentials and IPv6 for external traffic.
// ============================================================================

// TestDaemonHostNamespace tests the ecs-bridge plugin's ability to create
// a daemon namespace with connectivity to both the ECS credentials endpoint
// (via IPv4 link-local) and external networks (via IPv4 or IPv6 depending
// on host support).
//
// The test creates a "daemon-host-ns" namespace connected to the outside world
// via a bridge, supporting both IPv4-only and IPv6-only hosts. The primary
// purpose is to expose and help diagnose IPv6 bugs in the current ecs-bridge
// and IPAM implementation.
//
// Test structure:
// - Common setup: log directory, IPAM database, plugin path discovery
// - IPv4Only sub-test: Tests IPv4-only configuration
// - IPv6Only sub-test: Tests IPv6-only configuration (key for exposing bugs)
// - DualStack sub-test: Tests dual-stack configuration
func TestDaemonHostNamespace(t *testing.T) {
	// ========================================================================
	// Common Setup
	// ========================================================================

	// Detect host IP version support and log which versions are supported
	// This validates Requirements 1.1, 1.2: Detect IPv4 and IPv6 support
	hasIPv4 := instanceSupportsIPv4()
	hasIPv6 := instanceSupportsIPv6()

	// Log which IP versions are supported (Requirement 8.4)
	t.Logf("Host IP version support: IPv4=%v, IPv6=%v", hasIPv4, hasIPv6)

	// Skip the entire test if neither IPv4 nor IPv6 is supported
	// This validates Requirement 1.3: Skip if no IP support
	if !hasIPv4 && !hasIPv6 {
		t.Skip("Skipping test: host supports neither IPv4 nor IPv6")
	}

	// Ensure that the bridge plugin exists
	bridgePluginPath, err := invoke.FindInPath("ecs-bridge", []string{os.Getenv("CNI_PATH")})
	require.NoError(t, err, "Unable to find bridge plugin in path")
	t.Logf("Using bridge plugin: %s", bridgePluginPath)

	// Create a directory for storing test logs
	testLogDir, err := ioutil.TempDir("", "ecs-bridge-e2e-daemon-")
	require.NoError(t, err, "Unable to create directory for storing test logs")

	// Configure the env var to use the test logs directory
	os.Setenv("ECS_CNI_LOG_FILE", fmt.Sprintf("%s/bridge.log", testLogDir))
	t.Logf("Using %s for test logs", testLogDir)
	defer os.Unsetenv("ECS_CNI_LOG_FILE")

	// Handle deletion of test logs at the end of the test execution if specified
	// This validates Requirement 8.5: Preserve logs if ECS_PRESERVE_E2E_TEST_LOGS is set
	preserveLogs, err := strconv.ParseBool(getEnvOrDefault("ECS_PRESERVE_E2E_TEST_LOGS", "false"))
	assert.NoError(t, err, "Unable to parse ECS_PRESERVE_E2E_TEST_LOGS env var")
	defer func(preserve bool) {
		if !t.Failed() && !preserve {
			os.RemoveAll(testLogDir)
		}
	}(preserveLogs)

	// ========================================================================
	// Sub-tests for different IP version scenarios
	// ========================================================================

	// IPv4-only sub-test
	// This validates Requirement 1.4: Run IPv4-specific tests when host supports only IPv4
	t.Run("IPv4Only", func(t *testing.T) {
		skipIfNoIPv4(t)
		t.Logf("Running IPv4-only daemon host namespace test")

		// Create a directory to store IPAM db for this sub-test
		ipamDir, err := ioutil.TempDir("", "ecs-ipam-daemon-ipv4-")
		require.NoError(t, err, "Unable to create a temp directory for the ipam db")
		os.Setenv("IPAM_DB_PATH", fmt.Sprintf("%s/ipam.db", ipamDir))
		defer os.Unsetenv("IPAM_DB_PATH")
		preserveIPAM, err := strconv.ParseBool(getEnvOrDefault("ECS_BRIDGE_PRESERVE_IPAM_DB", "false"))
		assert.NoError(t, err, "Unable to parse ECS_BRIDGE_PRESERVE_IPAM_DB env var")
		if !preserveIPAM {
			defer os.RemoveAll(ipamDir)
		}

		// Create test and target namespaces
		// This validates Requirement 2.1: Create daemon-host-ns namespace
		testNS, err := ns.NewNS()
		require.NoError(t, err, "Unable to create the network namespace to run the test in")
		defer testNS.Close()

		// Create a network namespace to mimic the daemon's network namespace
		// This validates Requirement 2.2: Create bridge device to connect namespace
		targetNS, err := ns.NewNS()
		require.NoError(t, err, "Unable to create the network namespace that represents the daemon namespace")
		defer targetNS.Close()

		// Construct args to invoke the CNI plugin with
		// This validates Requirement 7.3: Provide valid CNI configuration
		execInvokeArgs := &invoke.Args{
			ContainerID: daemonContainerID,
			NetNS:       targetNS.Path(),
			IfName:      daemonIfName,
			Path:        os.Getenv("CNI_PATH"),
		}

		// Variable to hold veth reference for cleanup validation
		var vethTestNetNS netlink.Link
		var ok bool

		// Execute ADD command in test namespace
		// This validates Requirement 7.1: Invoke ecs-bridge CNI plugin with ADD command
		testNS.Do(func(ns.NetNS) error {
			execInvokeArgs.Command = "ADD"
			_, err := invoke.ExecPluginWithResult(
				bridgePluginPath,
				[]byte(fmt.Sprintf(netConfDaemonIPv4Only, daemonBridgeName)),
				execInvokeArgs)
			require.NoError(t, err, "Unable to execute ADD command for ecs-bridge plugin with IPv4-only daemon config")

			// Validate that bridge was created with the expected IPv4 link-local address
			// **Feature: daemon-host-ns-e2e-test, Property 1: IPv4 Link-Local Configuration Invariant**
			// This validates Requirement 2.3: Bridge configured with ECS_Link_Local_Subnet gateway
			bridge, err := netlink.LinkByName(daemonBridgeName)
			require.NoError(t, err, "Unable to find daemon bridge: %s", daemonBridgeName)
			validateDaemonBridgeIPv4(t, bridge)

			// Validate that veth pair device was created
			// This validates Requirement 2.4: Veth pair created connecting namespace to bridge
			vethTestNetNS, ok = getVethAndVerifyLo(t)
			require.True(t, ok, "veth device not found in test netns")
			return nil
		})

		// Stop if ADD command failed
		if t.Failed() {
			return
		}

		// Validate target namespace configuration
		var vethTargetNetNS netlink.Link
		targetNS.Do(func(ns.NetNS) error {
			// Validate the daemon end of the veth pair has the desired address
			// This validates Requirement 2.5: IP address assigned from ECS_Link_Local_Subnet
			vethTargetNetNS, ok = getVethAndVerifyLo(t)
			require.True(t, ok, "veth device not found in target netns")

			// Validate veth IPv4 address
			// **Feature: daemon-host-ns-e2e-test, Property 1: IPv4 Link-Local Configuration Invariant**
			// This validates Requirement 3.2: Veth has IPv4 address from ECS_Link_Local_Subnet
			validateDaemonVethIPv4(t, vethTargetNetNS)

			// Validate IPv4 routes including ECS credentials endpoint
			// **Feature: daemon-host-ns-e2e-test, Property 1: IPv4 Link-Local Configuration Invariant**
			// This validates Requirement 3.3: Route to ECS_Credentials_Endpoint exists
			validateDaemonRoutesIPv4(t, vethTargetNetNS)

			// Log network state for debugging
			logNetworkState(t, targetNS, "After ADD - IPv4Only")
			return nil
		})

		// Stop if validation failed
		if t.Failed() {
			return
		}

		// Execute DEL command to clean up
		// This validates Requirement 7.2: Invoke ecs-bridge CNI plugin with DEL command
		testNS.Do(func(ns.NetNS) error {
			execInvokeArgs.Command = "DEL"
			err := invoke.ExecPluginWithoutResult(
				bridgePluginPath,
				[]byte(fmt.Sprintf(netConfDaemonIPv4Only, daemonBridgeName)),
				execInvokeArgs)
			require.NoError(t, err, "Unable to execute DEL command for ecs-bridge plugin")

			// Validate veth interface is removed in test namespace
			// **Feature: daemon-host-ns-e2e-test, Property 4: Cleanup Invariant**
			// This validates Requirement 6.3: Veth pairs deleted
			validateLinkDoesNotExist(t, vethTestNetNS.Attrs().Name)

			// Validate that the bridge address remains unaltered (bridge persists)
			// This validates Requirement 6.2: Bridge device cleanup
			bridge, err := netlink.LinkByName(daemonBridgeName)
			require.NoError(t, err, "Bridge should still exist after DEL")
			validateDaemonBridgeIPv4(t, bridge)
			return nil
		})

		// Validate cleanup in target namespace
		// **Feature: daemon-host-ns-e2e-test, Property 4: Cleanup Invariant**
		// This validates Requirement 6.5: Verify resources no longer exist
		targetNS.Do(func(ns.NetNS) error {
			validateLinkDoesNotExist(t, vethTargetNetNS.Attrs().Name)
			return nil
		})

		t.Log("IPv4-only daemon host namespace test completed successfully")
	})

	// IPv6-only sub-test
	// This is the key test for exposing IPv6 bugs in the ecs-bridge implementation
	// This validates Requirement 1.5: Run IPv6-specific tests when host supports only IPv6
	t.Run("IPv6Only", func(t *testing.T) {
		skipIfNoIPv6(t)
		t.Logf("Running IPv6-only daemon host namespace test")
		t.Logf("NOTE: This test uses IPv4 link-local for ECS credentials + IPv6 for external traffic")

		// Create a directory to store IPAM db for this sub-test
		ipamDir, err := ioutil.TempDir("", "ecs-ipam-daemon-ipv6-")
		require.NoError(t, err, "Unable to create a temp directory for the ipam db")
		os.Setenv("IPAM_DB_PATH", fmt.Sprintf("%s/ipam.db", ipamDir))
		defer os.Unsetenv("IPAM_DB_PATH")
		preserveIPAM, err := strconv.ParseBool(getEnvOrDefault("ECS_BRIDGE_PRESERVE_IPAM_DB", "false"))
		assert.NoError(t, err, "Unable to parse ECS_BRIDGE_PRESERVE_IPAM_DB env var")
		if !preserveIPAM {
			defer os.RemoveAll(ipamDir)
		}

		// Create test and target namespaces
		// This validates Requirement 2.1: Create daemon-host-ns namespace
		testNS, err := ns.NewNS()
		require.NoError(t, err, "Unable to create the network namespace to run the test in")
		defer testNS.Close()

		// Create a network namespace to mimic the daemon's network namespace
		// This validates Requirement 2.2: Create bridge device to connect namespace
		targetNS, err := ns.NewNS()
		require.NoError(t, err, "Unable to create the network namespace that represents the daemon namespace")
		defer targetNS.Close()

		// Construct args to invoke the CNI plugin with
		// This validates Requirement 7.3: Provide valid CNI configuration
		execInvokeArgs := &invoke.Args{
			ContainerID: daemonContainerID,
			NetNS:       targetNS.Path(),
			IfName:      daemonIfName,
			Path:        os.Getenv("CNI_PATH"),
		}

		// Variable to hold veth reference for cleanup validation
		var vethTestNetNS netlink.Link
		var ok bool

		// Execute ADD command in test namespace
		// This validates Requirement 7.1: Invoke ecs-bridge CNI plugin with ADD command
		testNS.Do(func(ns.NetNS) error {
			execInvokeArgs.Command = "ADD"
			_, err := invoke.ExecPluginWithResult(
				bridgePluginPath,
				[]byte(fmt.Sprintf(netConfDaemonIPv6Only, daemonBridgeName)),
				execInvokeArgs)
			require.NoError(t, err, "Unable to execute ADD command for ecs-bridge plugin with IPv6-only daemon config")

			// Validate that bridge was created with the expected IPv4 link-local address
			// **Feature: daemon-host-ns-e2e-test, Property 1: IPv4 Link-Local Configuration Invariant**
			// This validates Requirement 2.3: Bridge configured with ECS_Link_Local_Subnet gateway
			bridge, err := netlink.LinkByName(daemonBridgeName)
			require.NoError(t, err, "Unable to find daemon bridge: %s", daemonBridgeName)
			validateDaemonBridgeIPv4(t, bridge)

			// Validate that bridge was created with the expected IPv6 address
			// **Feature: daemon-host-ns-e2e-test, Property 2: IPv6 Configuration Invariant**
			// This validates Requirement 4.1: Bridge has expected IPv6 address
			validateDaemonBridgeIPv6(t, bridge)

			// Validate that veth pair device was created
			// This validates Requirement 2.4: Veth pair created connecting namespace to bridge
			vethTestNetNS, ok = getVethAndVerifyLo(t)
			require.True(t, ok, "veth device not found in test netns")
			return nil
		})

		// Stop if ADD command failed
		if t.Failed() {
			// Log network state for debugging before returning
			testNS.Do(func(ns.NetNS) error {
				logNetworkState(t, testNS, "After ADD failure - IPv6Only (test namespace)")
				return nil
			})
			return
		}

		// Validate target namespace configuration
		var vethTargetNetNS netlink.Link
		targetNS.Do(func(ns.NetNS) error {
			// Validate the daemon end of the veth pair has the desired address
			// This validates Requirement 2.5: IP address assigned from ECS_Link_Local_Subnet
			vethTargetNetNS, ok = getVethAndVerifyLo(t)
			require.True(t, ok, "veth device not found in target netns")

			// Validate veth IPv4 address (for ECS credentials endpoint)
			// **Feature: daemon-host-ns-e2e-test, Property 1: IPv4 Link-Local Configuration Invariant**
			// This validates Requirement 3.2: Veth has IPv4 address from ECS_Link_Local_Subnet
			validateDaemonVethIPv4(t, vethTargetNetNS)

			// Validate veth IPv6 address (for external traffic)
			// **Feature: daemon-host-ns-e2e-test, Property 2: IPv6 Configuration Invariant**
			// This validates Requirement 4.2: Veth has IPv6 address
			validateDaemonVethIPv6(t, vethTargetNetNS)

			// Validate IPv4 routes including ECS credentials endpoint
			// **Feature: daemon-host-ns-e2e-test, Property 1: IPv4 Link-Local Configuration Invariant**
			// This validates Requirement 3.3: Route to ECS_Credentials_Endpoint exists
			validateDaemonRoutesIPv4(t, vethTargetNetNS)

			// Validate IPv6 default route for external traffic
			// **Feature: daemon-host-ns-e2e-test, Property 2: IPv6 Configuration Invariant**
			// This validates Requirements 4.3, 4.4: IPv6 default route exists with correct gateway
			validateDaemonRoutesIPv6(t, vethTargetNetNS)

			// Log network state for debugging
			// This validates Requirement 4.5: Report failure with detailed diagnostic information
			logNetworkState(t, targetNS, "After ADD - IPv6Only")
			return nil
		})

		// Stop if validation failed
		if t.Failed() {
			return
		}

		// Execute DEL command to clean up
		// This validates Requirement 7.2: Invoke ecs-bridge CNI plugin with DEL command
		testNS.Do(func(ns.NetNS) error {
			execInvokeArgs.Command = "DEL"
			err := invoke.ExecPluginWithoutResult(
				bridgePluginPath,
				[]byte(fmt.Sprintf(netConfDaemonIPv6Only, daemonBridgeName)),
				execInvokeArgs)
			require.NoError(t, err, "Unable to execute DEL command for ecs-bridge plugin")

			// Validate veth interface is removed in test namespace
			// **Feature: daemon-host-ns-e2e-test, Property 4: Cleanup Invariant**
			// This validates Requirement 6.3: Veth pairs deleted
			validateLinkDoesNotExist(t, vethTestNetNS.Attrs().Name)

			// Validate that the bridge addresses remain unaltered (bridge persists)
			// This validates Requirement 6.2: Bridge device cleanup
			bridge, err := netlink.LinkByName(daemonBridgeName)
			require.NoError(t, err, "Bridge should still exist after DEL")
			validateDaemonBridgeIPv4(t, bridge)
			validateDaemonBridgeIPv6(t, bridge)
			return nil
		})

		// Validate cleanup in target namespace
		// **Feature: daemon-host-ns-e2e-test, Property 4: Cleanup Invariant**
		// This validates Requirement 6.5: Verify resources no longer exist
		targetNS.Do(func(ns.NetNS) error {
			validateLinkDoesNotExist(t, vethTargetNetNS.Attrs().Name)
			return nil
		})

		t.Log("IPv6-only daemon host namespace test completed successfully")
	})

	// Dual-stack sub-test
	// This validates Requirement 1.6: Run both IPv4 and IPv6 tests when host supports both
	t.Run("DualStack", func(t *testing.T) {
		skipIfNoDualStack(t)
		t.Logf("Running dual-stack daemon host namespace test")
		t.Logf("NOTE: This test uses IPv4 link-local for ECS credentials + IPv6 for external traffic")

		// Create a directory to store IPAM db for this sub-test
		ipamDir, err := ioutil.TempDir("", "ecs-ipam-daemon-dualstack-")
		require.NoError(t, err, "Unable to create a temp directory for the ipam db")
		os.Setenv("IPAM_DB_PATH", fmt.Sprintf("%s/ipam.db", ipamDir))
		defer os.Unsetenv("IPAM_DB_PATH")
		preserveIPAM, err := strconv.ParseBool(getEnvOrDefault("ECS_BRIDGE_PRESERVE_IPAM_DB", "false"))
		assert.NoError(t, err, "Unable to parse ECS_BRIDGE_PRESERVE_IPAM_DB env var")
		if !preserveIPAM {
			defer os.RemoveAll(ipamDir)
		}

		// Create test and target namespaces
		// This validates Requirement 2.1: Create daemon-host-ns namespace
		testNS, err := ns.NewNS()
		require.NoError(t, err, "Unable to create the network namespace to run the test in")
		defer testNS.Close()

		// Create a network namespace to mimic the daemon's network namespace
		// This validates Requirement 2.2: Create bridge device to connect namespace
		targetNS, err := ns.NewNS()
		require.NoError(t, err, "Unable to create the network namespace that represents the daemon namespace")
		defer targetNS.Close()

		// Construct args to invoke the CNI plugin with
		// This validates Requirement 7.3: Provide valid CNI configuration
		execInvokeArgs := &invoke.Args{
			ContainerID: daemonContainerID,
			NetNS:       targetNS.Path(),
			IfName:      daemonIfName,
			Path:        os.Getenv("CNI_PATH"),
		}

		// Variable to hold veth reference for cleanup validation
		var vethTestNetNS netlink.Link
		var ok bool

		// Execute ADD command in test namespace
		// This validates Requirement 7.1: Invoke ecs-bridge CNI plugin with ADD command
		testNS.Do(func(ns.NetNS) error {
			execInvokeArgs.Command = "ADD"
			_, err := invoke.ExecPluginWithResult(
				bridgePluginPath,
				[]byte(fmt.Sprintf(netConfDaemonDualStack, daemonBridgeName)),
				execInvokeArgs)
			require.NoError(t, err, "Unable to execute ADD command for ecs-bridge plugin with dual-stack daemon config")

			// Validate that bridge was created with the expected IPv4 link-local address
			// **Feature: daemon-host-ns-e2e-test, Property 3: Dual-Stack Configuration Invariant**
			// This validates Requirement 5.1: Both IPv4 link-local and IPv6 addressing on bridge
			bridge, err := netlink.LinkByName(daemonBridgeName)
			require.NoError(t, err, "Unable to find daemon bridge: %s", daemonBridgeName)
			validateDaemonBridgeIPv4(t, bridge)

			// Validate that bridge was created with the expected IPv6 address
			// **Feature: daemon-host-ns-e2e-test, Property 3: Dual-Stack Configuration Invariant**
			// This validates Requirement 5.1: Both IPv4 link-local and IPv6 addressing on bridge
			validateDaemonBridgeIPv6(t, bridge)

			// Validate that veth pair device was created
			// This validates Requirement 2.4: Veth pair created connecting namespace to bridge
			vethTestNetNS, ok = getVethAndVerifyLo(t)
			require.True(t, ok, "veth device not found in test netns")
			return nil
		})

		// Stop if ADD command failed
		if t.Failed() {
			// Log network state for debugging before returning
			testNS.Do(func(ns.NetNS) error {
				logNetworkState(t, testNS, "After ADD failure - DualStack (test namespace)")
				return nil
			})
			return
		}

		// Validate target namespace configuration
		var vethTargetNetNS netlink.Link
		targetNS.Do(func(ns.NetNS) error {
			// Validate the daemon end of the veth pair has the desired address
			// This validates Requirement 2.5: IP address assigned from ECS_Link_Local_Subnet
			vethTargetNetNS, ok = getVethAndVerifyLo(t)
			require.True(t, ok, "veth device not found in target netns")

			// Validate veth IPv4 address (for ECS credentials endpoint)
			// **Feature: daemon-host-ns-e2e-test, Property 3: Dual-Stack Configuration Invariant**
			// This validates Requirement 5.2: IPv4 link-local for ECS credentials endpoint access
			validateDaemonVethIPv4(t, vethTargetNetNS)

			// Validate veth IPv6 address (for external traffic)
			// **Feature: daemon-host-ns-e2e-test, Property 3: Dual-Stack Configuration Invariant**
			// This validates Requirement 5.3: IPv6 for external traffic routing
			validateDaemonVethIPv6(t, vethTargetNetNS)

			// Validate IPv4 routes including ECS credentials endpoint
			// **Feature: daemon-host-ns-e2e-test, Property 3: Dual-Stack Configuration Invariant**
			// This validates Requirement 5.4: IPv4 routes to ECS_Credentials_Endpoint correctly configured
			validateDaemonRoutesIPv4(t, vethTargetNetNS)

			// Validate IPv6 default route for external traffic
			// **Feature: daemon-host-ns-e2e-test, Property 3: Dual-Stack Configuration Invariant**
			// This validates Requirement 5.5: IPv6 default routes for external traffic correctly configured
			validateDaemonRoutesIPv6(t, vethTargetNetNS)

			// Log network state for debugging
			logNetworkState(t, targetNS, "After ADD - DualStack")
			return nil
		})

		// Stop if validation failed
		if t.Failed() {
			return
		}

		// Execute DEL command to clean up
		// This validates Requirement 7.2: Invoke ecs-bridge CNI plugin with DEL command
		testNS.Do(func(ns.NetNS) error {
			execInvokeArgs.Command = "DEL"
			err := invoke.ExecPluginWithoutResult(
				bridgePluginPath,
				[]byte(fmt.Sprintf(netConfDaemonDualStack, daemonBridgeName)),
				execInvokeArgs)
			require.NoError(t, err, "Unable to execute DEL command for ecs-bridge plugin")

			// Validate veth interface is removed in test namespace
			// **Feature: daemon-host-ns-e2e-test, Property 4: Cleanup Invariant**
			// This validates Requirement 6.3: Veth pairs deleted
			validateLinkDoesNotExist(t, vethTestNetNS.Attrs().Name)

			// Validate that the bridge addresses remain unaltered (bridge persists)
			// This validates Requirement 6.2: Bridge device cleanup
			bridge, err := netlink.LinkByName(daemonBridgeName)
			require.NoError(t, err, "Bridge should still exist after DEL")
			validateDaemonBridgeIPv4(t, bridge)
			validateDaemonBridgeIPv6(t, bridge)
			return nil
		})

		// Validate cleanup in target namespace
		// **Feature: daemon-host-ns-e2e-test, Property 4: Cleanup Invariant**
		// This validates Requirement 6.5: Verify resources no longer exist
		targetNS.Do(func(ns.NetNS) error {
			validateLinkDoesNotExist(t, vethTargetNetNS.Attrs().Name)
			return nil
		})

		t.Log("Dual-stack daemon host namespace test completed successfully")
	})
}
