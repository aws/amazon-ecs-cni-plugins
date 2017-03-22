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

package utils

import (
	"net"
	"testing"

	"github.com/aws/amazon-ecs-cni-plugins/plugins/ipam/config"
	"github.com/aws/amazon-ecs-cni-plugins/plugins/ipam/ipstore/mocks"
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
		allocator.EXPECT().Exists("10.0.0.3").Return(false, nil),
		allocator.EXPECT().Assign(gomock.Any(), gomock.Any()).Return(nil),
		allocator.EXPECT().SetLastKnownIP(net.ParseIP("10.0.0.3")),
	)
	assignedAddress, err := GetIPV4Address(allocator, conf)
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
	assignedAddress, err := GetIPV4Address(allocator, conf)
	assert.NoError(t, err, "get available ip from subnet failed")
	assert.Equal(t, "10.0.0.4/29", assignedAddress.String(), "Assigned ip should be the next available ip")
}

// TestGetUsedIPv4 tests if the specified ip has already been used, it will cause error
func TestGetUsedIPv4(t *testing.T) {
	conf, allocator := setup("10.0.0.0/29", "10.0.0.3/29", "", t)

	gomock.InOrder(
		allocator.EXPECT().Exists("10.0.0.3").Return(true, nil),
	)

	assignedAddress, err := GetIPV4Address(allocator, conf)
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

	assignedAddress, err := GetIPV4Address(allocator, conf)
	assert.Error(t, err, "no available ip in the subnet should cause error")
	assert.Nil(t, assignedAddress, "error will cause ip not be assigned")
}

// TestGWUsed tests the default gateway can be used by multiple container
func TestGWUsed(t *testing.T) {
	_, allocator := setup("10.0.0.0/29", "", "", t)
	gw := "10.0.0.1"

	gomock.InOrder(
		allocator.EXPECT().Exists(gw).Return(true, nil),
		allocator.EXPECT().Get(gw).Return(config.GatewayValue, nil),
	)

	err := VerifyGateway(net.ParseIP("10.0.0.1"), allocator)
	assert.NoError(t, err, "gateway can be used by multiple containers")
}

func TestConstructResult(t *testing.T) {
	conf, _ := setup("10.0.0.0/29", "", "", t)

	tip, tsub, err := net.ParseCIDR("10.0.0.1/29")
	assert.NoError(t, err, "Parsing the cidr failed")
	ip := net.IPNet{
		IP:   tip,
		Mask: tsub.Mask,
	}

	result := ConstructResults(conf, ip)
	assert.NotNil(t, result, "Construct result for bridge plugin failed")
	assert.Equal(t, 1, len(result.IPs), "Only one ip should be assigned each time")
}
