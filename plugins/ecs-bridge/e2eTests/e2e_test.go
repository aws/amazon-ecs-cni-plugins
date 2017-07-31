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
)

func init() {
	runtime.LockOSThread()
}

type configureNetNSFunc func() error

func TestAddDel(t *testing.T) {
	testCases := map[string]configureNetNSFunc{
		"When Bridge Exists":                                configureNetNSWithBridge,
		"When Bridge Exists And Configured With IP Address": configureNetNSWithBridgeAndSetIPAddress,
		"When Bridge Does Not Exist":                        configureNetNSNop,
	}

	bridgePluginPath, err := invoke.FindInPath("ecs-bridge", []string{os.Getenv("CNI_PATH")})
	require.NoError(t, err, "Unable to find bridge plugin in path")

	testLogDir, err := ioutil.TempDir("", "ecs-bridge-e2e-test-")
	require.NoError(t, err, "Unable to create directory for storing test logs")

	os.Setenv("ECS_CNI_LOG_FILE", fmt.Sprintf("%s/bridge.log", testLogDir))
	t.Logf("Using %s for test logs", testLogDir)
	defer os.Unsetenv("ECS_CNI_LOG_FILE")

	ok, err := strconv.ParseBool(getEnvOrDefault("ECS_PRESERVE_E2E_TEST_LOGS", "false"))
	assert.NoError(t, err, "Unable to parse ECS_PRESERVE_E2E_TEST_LOGS env var")
	if !ok {
		defer os.RemoveAll(testLogDir)
	}

	for tcName, configFunc := range testCases {
		t.Run(tcName, func(t *testing.T) {
			testNS, err := ns.NewNS()
			require.NoError(t, err, "Unable to create the network namespace to run the test in")
			defer testNS.Close()

			targetNS, err := ns.NewNS()
			require.NoError(t, err,
				"Unable to create the network namespace that represents the network namespace of the container")
			defer targetNS.Close()

			ipamDir, err := ioutil.TempDir("", "ecs-ipam-")
			require.NoError(t, err, "Unable to create a temp directory for the ipam db")
			os.Setenv("IPAM_DB_PATH", fmt.Sprintf("%s/ipam.db", ipamDir))
			defer os.Unsetenv("IPAM_DB_PATH")
			ok, err := strconv.ParseBool(getEnvOrDefault("ECS_BRIDGE_PRESERVE_IPAM_DB", "false"))
			assert.NoError(t, err, "Unable to parse ECS_BRIDGE_PRESERVE_IPAM_DB env var")
			if !ok {
				defer os.RemoveAll(ipamDir)
			}

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

				execInvokeArgs.Command = "ADD"
				_, err := invoke.ExecPluginWithResult(
					bridgePluginPath,
					[]byte(fmt.Sprintf(netConf, bridgeName, dst)),
					execInvokeArgs)
				require.NoError(t, err, "Unable to execute ADD command for ecs-bridge plugin")

				bridge := getBridgeLink(t)
				validateBridgeAddress(t, bridge)
				vethTestNetNS, ok = getVeth(t)
				require.True(t, ok, "veth device not found in test netns")
				return nil
			})

			var vethTargetNetNS netlink.Link
			targetNS.Do(func(ns.NetNS) error {
				vethTargetNetNS, ok = getVeth(t)
				require.True(t, ok, "veth device not found in target netns")
				validateVethAddress(t, vethTargetNetNS)
				validateRouteForVethInTargetNetNS(t, vethTargetNetNS)
				return nil
			})

			testNS.Do(func(ns.NetNS) error {
				execInvokeArgs.Command = "DEL"
				err := invoke.ExecPluginWithoutResult(
					bridgePluginPath,
					[]byte(fmt.Sprintf(netConf, bridgeName, dst)),
					execInvokeArgs)
				require.NoError(t, err, "Unable to execute DEL command for ecs-bridge plugin")

				validateLinkDoesNotExist(t, vethTestNetNS.Attrs().Name)
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

func configureNetNSWithBridge() error {
	bridgeLinkAttributes := netlink.NewLinkAttrs()
	bridgeLinkAttributes.Name = bridgeName

	return netlink.LinkAdd(&netlink.Bridge{
		LinkAttrs: bridgeLinkAttributes,
	})
}

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

func getEnvOrDefault(name string, fallback string) string {
	val := os.Getenv(name)
	if val == "" {
		return fallback
	}

	return val
}

func getBridgeLink(t *testing.T) netlink.Link {
	bridgeLink, err := netlink.LinkByName(bridgeName)
	require.NoError(t, err, "Unable to find bridge: %s", bridgeName)
	_, ok := bridgeLink.(*netlink.Bridge)
	require.True(t, ok, "Link named '%s' is not a bridge", bridgeName)
	return bridgeLink
}

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

func getVeth(t *testing.T) (netlink.Link, bool) {
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

func validateRouteForVethInTargetNetNS(t *testing.T, veth netlink.Link) {
	routes, err := netlink.RouteList(veth, netlink.FAMILY_V4)
	require.NoError(t, err, "Unable to list routes for: %s", veth.Attrs().Name)
	routeFound := false
	for _, route := range routes {
		if route.Dst.String() == dst &&
			route.Src == nil &&
			route.Gw.String() == expectedGateway {
			routeFound = true
		}
	}
	require.True(t, routeFound, "Route with gateway '%s' not found for: %s",
		expectedGateway, veth.Attrs().Name)
}

func validateLinkDoesNotExist(t *testing.T, name string) {
	_, err := netlink.LinkByName(name)
	require.Error(t, err, "Link %s should not exist", name)
	_, ok := err.(netlink.LinkNotFoundError)
	require.True(t, ok, "Error type is incorrect for link: %s", name)
}
