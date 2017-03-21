// +build integration
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

package main

import (
	"io/ioutil"
	"net"
	"os"
	"testing"

	"github.com/aws/amazon-ecs-cni-plugins/plugins/ipam/config"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testdb     = "/tmp/ipam_test"
	testBucket = "ipam"
)

func init() {
	os.Setenv(config.EnvDBName, testdb)
	os.Setenv(config.EnvBucketName, testBucket)
}

func cleanup(t *testing.T) {
	_, err := os.Stat(testdb)
	if err != nil {
		require.True(t, os.IsNotExist(err), "if it's not file not exist error, then there should be a problem: %v", err)
	} else {
		err = os.Remove(testdb)
		require.NoError(t, err, "Remove the existed db should not cause error")
	}
}

// TestGetExistedIP tests get an used IP from the ipv4-subnet will cause error
func TestGetExistedIP(t *testing.T) {
	defer cleanup(t)
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"ipv4-address": "10.0.0.2/24",
				"timeout": "5s",
				"ipv4-subnet": "10.0.0.0/24",
				"ipv4-gateway": "10.0.0.8",
				"routes": [
				{"dst": "192.168.2.3/32"}
				]
			}
		}`

	args := &skel.CmdArgs{
		StdinData: []byte(conf),
	}
	err := cmdAdd(args)
	assert.NoError(t, err, "expect no error")

	// Try to acquire the used IP
	err = cmdAdd(args)
	assert.Error(t, err, "expect error for requiring used IP")
}

// TestGetAvailableIPv4 tests the ipam will assign an available IP from the ipv4-subnet
func TestGetAvailableIPv4(t *testing.T) {
	defer cleanup(t)
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"timeout": "5s",
				"ipv4-subnet": "10.0.0.0/24",
				"ipv4-gateway": "10.0.0.8",
				"routes": [
				{"dst": "192.168.2.3/32"}
				]
			}
		}`

	// redirect the stdout to capture the returned output
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err, "expect redirect os.stdin succeed")

	os.Stdout = w

	args := &skel.CmdArgs{
		StdinData: []byte(conf),
	}
	err = cmdAdd(args)
	assert.NoError(t, err, "expect no error")
	w.Close()

	output, err := ioutil.ReadAll(r)
	os.Stdout = oldStdout
	require.NoError(t, err, "expect reading from stdin succeed")

	res, _ := version.NewResult("0.3.0", output)
	result, err := current.GetResult(res)
	require.NoError(t, err, "expect the result has correct format")

	assert.Equal(t, result.IPs[0].Gateway, net.ParseIP("10.0.0.8"), "result should be same as configured")
	assert.Equal(t, result.IPs[0].Address.IP, net.ParseIP("10.0.0.1"), "result should be same as configured")
	assert.Equal(t, result.Routes[0].Dst.String(), "192.168.2.3/32", "result should be same as configured")
}

// TestDel tests the DEL command of ipam plugin
func TestDel(t *testing.T) {
	defer cleanup(t)
	conf := `{
			"name": "testnet",
			"cniVersion": "0.3.0",
			"ipam": {
				"type": "ipam",
				"timeout": "5s",
				"ipv4-subnet": "10.0.0.0/24",
				"ipv4-address": "10.0.0.3/24",
				"ipv4-gateway": "10.0.0.8",
				"routes": [
				{"dst": "192.168.2.3/32"}
				]
			}
		}`

	args := &skel.CmdArgs{
		StdinData: []byte(conf),
	}

	err := cmdDel(args)
	assert.Error(t, err, "release an available ip should cause error")

	err = cmdAdd(args)
	assert.NoError(t, err, "expect no error")

	err = cmdAdd(args)
	assert.Error(t, err, "use existed ip should cause error")

	err = cmdDel(args)
	assert.NoError(t, err, "delete an used ip from db should succeed")

	// redirect the stdout to capture the returned output
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err, "expect redirect os.stdin succeed")

	os.Stdout = w
	err = cmdAdd(args)
	assert.NoError(t, err, "use a released ip should success")

	w.Close()

	output, err := ioutil.ReadAll(r)
	os.Stdout = oldStdout
	require.NoError(t, err, "expect reading from stdin succeed")

	res, _ := version.NewResult("0.3.0", output)
	result, err := current.GetResult(res)
	require.NoError(t, err, "expect the result has correct format")

	assert.Equal(t, result.IPs[0].Gateway, net.ParseIP("10.0.0.8"), "result should be same as configured")
	assert.Equal(t, result.IPs[0].Address.IP, net.ParseIP("10.0.0.3"), "result should be same as configured")
	assert.Equal(t, result.Routes[0].Dst.String(), "192.168.2.3/32", "result should be same as configured")
}
