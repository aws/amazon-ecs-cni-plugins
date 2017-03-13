// Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package ipstore

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/docker/libkv/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	subnet     = "169.254.172.0/22"
	testdb     = "/tmp/__boltdb_test"
	testBucket = "ipmanager"
)

func setup(t *testing.T) *IPManager {
	_, err := os.Stat(testdb)
	if err != nil {
		require.True(t, os.IsNotExist(err), "if it's not file not exist error, then there should be a problem: %v", err)
	} else {
		err = os.Remove(testdb)
		require.NoError(t, err, "Remove the existed db should not cause error")
	}

	_, subnet, err := net.ParseCIDR(subnet)
	require.NoError(t, err)

	ipManager, err := New(&Config{DB: testdb, PersistConnection: true, Bucket: testBucket, ConnectionTimeout: 1 * time.Millisecond}, *subnet)
	require.NoError(t, err, "creating the IPManager failed")

	return ipManager
}

func TestAssignReleaseExistGetAvailableIP(t *testing.T) {
	ipManager := setup(t)
	defer ipManager.Close()

	ip, err := ipManager.GetAvailableIP("id")
	assert.NoError(t, err)
	assert.Equal(t, ip, "169.254.172.1")
	assert.Equal(t, 1, ipManager.allocated, "One ip address was allocated")

	exist, err := ipManager.Exists("169.254.172.1")
	assert.NoError(t, err)
	assert.True(t, exist)

	err = ipManager.Assign("169.254.172.1", "id2")
	assert.Error(t, err, "Assign to an used ip should casue error")
	assert.Equal(t, 1, ipManager.allocated)

	ip, err = ipManager.GetAvailableIP("id3")
	assert.NoError(t, err)
	assert.Equal(t, "169.254.172.2", ip, "ip should be allocated serially")
	assert.True(t, ipManager.lastKnownIP.Equal(net.ParseIP("169.254.172.2")), "ipmanager should record the recently referenced ip")
	assert.Equal(t, 2, ipManager.allocated)

	err = ipManager.Assign("169.254.172.3", "id")
	assert.NoError(t, err)
	assert.True(t, ipManager.lastKnownIP.Equal(net.ParseIP("169.254.172.3")), "ipmanager should record the recently reference ip")
	assert.Equal(t, 3, ipManager.allocated)

	exist, err = ipManager.Exists("169.254.172.1")
	assert.NoError(t, err)
	assert.True(t, exist, "ip has been assigned should existed in the db")

	exist, err = ipManager.Exists("169.254.172.2")
	assert.NoError(t, err)
	assert.True(t, exist, "ip has been assigned should existed in the db")

	exist, err = ipManager.Exists("169.254.172.3")
	assert.NoError(t, err)
	assert.True(t, exist, "ip has been assigned should existed in the db")

	err = ipManager.Release("169.254.172.1")
	assert.NoError(t, err)
	assert.True(t, ipManager.lastKnownIP.Equal(net.ParseIP("169.254.172.1")))
	assert.Equal(t, 2, ipManager.allocated, "number of ip allocated should decrease by 1 after releasing one")

	exist, err = ipManager.Exists("169.254.172.1")
	assert.NoError(t, err)
	assert.False(t, exist, "released ip address should not existed in the db")

	err = ipManager.Assign("169.254.172.1", "id")
	assert.NoError(t, err)
	assert.True(t, ipManager.lastKnownIP.Equal(net.ParseIP("169.254.172.1")), "ipmanager should record the recently reference ip")
	assert.Equal(t, 3, ipManager.allocated, "allocated one ip by Assign")
}

func TestGetExist(t *testing.T) {
	ipManager := setup(t)
	defer ipManager.Close()

	_, err := ipManager.Get("169.254.172.0")
	assert.Equal(t, err, store.ErrKeyNotFound, "Get an non-existed key should cause error")

	err = ipManager.Assign("169.254.170.0", "id1")
	assert.NoError(t, err)

	id, err := ipManager.Get("169.254.170.0")
	assert.NoError(t, err)
	assert.Equal(t, "id1", id)
}

func TestNextIPHappyPath(t *testing.T) {
	ipManager := setup(t)
	defer ipManager.Close()

	ip := net.ParseIP("10.0.0.3")
	_, subnet, err := net.ParseCIDR("10.0.0.0/24")
	assert.NoError(t, err)

	nextIP, err := NextIP(ip, *subnet)
	assert.NoError(t, err)
	assert.True(t, nextIP.Equal(net.ParseIP("10.0.0.4")), "next ip should return the next available ip")
}

func TestNextIPNotInSubnet(t *testing.T) {
	ipManager := setup(t)
	defer ipManager.Close()

	ip := net.ParseIP("10.0.0.3")
	_, subnet, err := net.ParseCIDR("10.1.0.0/16")
	assert.NoError(t, err)

	_, err = NextIP(ip, *subnet)
	assert.Error(t, err)
}

func TestGetAvailableIPSerially(t *testing.T) {
	ipManager := setup(t)
	defer ipManager.Close()

	ip, err := ipManager.GetAvailableIP("id")
	assert.NoError(t, err)
	assert.Equal(t, "169.254.172.1", ip)

	ip, err = ipManager.GetAvailableIP("id1")
	assert.NoError(t, err)
	assert.Equal(t, "169.254.172.2", ip, "ip should be assigned serially")
}
