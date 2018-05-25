// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeGatewayReturnsErrorOnMalformedCIDR(t *testing.T) {
	_, _, err := ComputeIPV4GatewayNetmask("1.1.1.1")
	assert.Error(t, err)
}

func TestComputeGatewayReturnsErrorOnMalformedNetmaskInCIDR(t *testing.T) {
	_, _, err := ComputeIPV4GatewayNetmask("1.1.1.1/")
	assert.Error(t, err)
}

func TestComputeGatewayReturnsErrorOnMalformedCIDRBlockInCIDR(t *testing.T) {
	_, _, err := ComputeIPV4GatewayNetmask("1.1.1/1")
	assert.Error(t, err)
}

func TestComputeGatewayReturnsErrorOnEmptyRouterInCIDR(t *testing.T) {
	_, _, err := ComputeIPV4GatewayNetmask("1.1.1./1")
	assert.Error(t, err)
}

func TestComputeGatewayReturnsErrorOnInvalidRouterInCIDR(t *testing.T) {
	_, _, err := ComputeIPV4GatewayNetmask("1.1.1.foo/1")
	assert.Error(t, err)
}

func TestComputeGatewayReturnsErrorOnInvalidCIDRBlock(t *testing.T) {
	_, _, err := ComputeIPV4GatewayNetmask("10.0.64.0/29")
	assert.Error(t, err)
	_, _, err = ComputeIPV4GatewayNetmask("10.0.64.0/15")
	assert.Error(t, err)
}

func TestComputeGateway(t *testing.T) {
	gateway, netmask, err := ComputeIPV4GatewayNetmask("10.0.1.64/26")
	assert.NoError(t, err)
	assert.Equal(t, gateway, "10.0.1.65")
	assert.Equal(t, netmask, "26")
}

func TestParseGatewayReturnsErrorOnMalformedCIDR(t *testing.T) {
	_, _, err := ParseIPV4GatewayNetmask("1.1.1.1")
	assert.Error(t, err)
}

func TestParseGatewayReturnsErrorOnMalformedNetmaskInCIDR(t *testing.T) {
	_, _, err := ParseIPV4GatewayNetmask("1.1.1.1/")
	assert.Error(t, err)
}

func TestParseGatewayReturnsErrorOnMalformedCIDRBlockInCIDR(t *testing.T) {
	_, _, err := ParseIPV4GatewayNetmask("1.1.1/1")
	assert.Error(t, err)
}

func TesParseGatewayReturnsErrorOnEmptyRouterInCIDR(t *testing.T) {
	_, _, err := ParseIPV4GatewayNetmask("1.1.1./1")
	assert.Error(t, err)
}

func TestParseGatewayReturnsErrorOnInvalidRouterInCIDR(t *testing.T) {
	_, _, err := ParseIPV4GatewayNetmask("1.1.1.foo/1")
	assert.Error(t, err)
}

func TestParseGateway(t *testing.T) {
	gateway, netmask, err := ParseIPV4GatewayNetmask("10.0.1.64/26")
	assert.NoError(t, err)
	assert.Equal(t, gateway, "10.0.1.64")
	assert.Equal(t, netmask, "26")
}
