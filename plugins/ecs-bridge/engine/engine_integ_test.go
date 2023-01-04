//go:build sudo && integration
// +build sudo,integration

// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
	"github.com/aws/amazon-ecs-cni-plugins/pkg/netlinkwrapper"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"net"
	"os"
	"testing"
)

const (
	testBridgeName    = "test-ecs-bridge"
	testMTU           = 1500
	testGatewayIPCIDR = "172.31.0.1"
	testdb            = "/tmp/__boltdb_test"
)

func cleanup(t *testing.T) {
	_, err := os.Stat(testdb)
	if err != nil {
		require.True(t, os.IsNotExist(err), "if it's not file not exist error, then there should be a problem: %v", err)
	} else {
		err = os.Remove(testdb)
		require.NoError(t, err, "Remove the existed db should not cause error")
	}

	// clean up the test bridge, if it's created
	testBridge, err := netlink.LinkByName(testBridgeName)
	if err == nil {
		err = netlink.LinkDel(testBridge)
		assert.NoError(t, err)
	}
}

func TestCreateBridgeAlreadyExists(t *testing.T) {
	defer cleanup(t)

	testEngine := &engine{
		netLink: netlinkwrapper.NewNetLink(),
	}
	err := testEngine.createBridge(testBridgeName, testMTU)
	require.NoError(t, err)

	// try creating the bridge again, expect getting a "file exists" error
	err = testEngine.createBridge(testBridgeName, testMTU)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), fileExistsErrMsg)
}

func TestConfigureBridgeNetworkAlreadyExists(t *testing.T) {
	defer cleanup(t)

	gatewayIPAddr := net.ParseIP(testGatewayIPCIDR)

	testEngine := &engine{
		netLink: netlinkwrapper.NewNetLink(),
	}

	ipConfig := &current.IPConfig{
		Address: net.IPNet{
			Mask: net.CIDRMask(31, 32),
		},
		Gateway: gatewayIPAddr,
	}

	result := &current.Result{
		IPs: []*current.IPConfig{ipConfig},
	}

	// create and configure a bridge
	testBridge, err := testEngine.CreateBridge(testBridgeName, testMTU)
	require.NoError(t, err)

	err = testEngine.ConfigureBridge(result, testBridge)
	require.NoError(t, err)

	// check that we get a "file exists" error when trying to assign same address to the bridge
	err = netlink.AddrAdd(testBridge, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   result.IPs[0].Gateway,
			Mask: result.IPs[0].Address.Mask,
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), fileExistsErrMsg)
}
