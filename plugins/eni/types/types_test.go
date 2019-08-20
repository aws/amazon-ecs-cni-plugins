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

package types

import (
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/stretchr/testify/assert"
)

var (
	validConfigNoIPV6                 = `{"eni":"eni1", "ipv4-address":"10.11.12.13", "mac":"01:23:45:67:89:ab"}`
	configNoENIID                     = `{"ipv4-address":"10.11.12.13", "mac":"01:23:45:67:89:ab"}`
	configNoIPV4Address               = `{"eni":"eni1", "mac":"01:23:45:67:89:ab"}`
	configNoMAC                       = `{"eni":"eni1", "ipv4-address":"10.11.12.13"}`
	configInvalidIPV4AddressMalformed = `{"eni":"eni1", "ipv4-address":"1", "mac":"01:23:45:67:89:ab"}`
	configInvalidIPV4AddressIPV6      = `{"eni":"eni1", "ipv4-address":"2001:db8::68", "mac":"01:23:45:67:89:ab"}`
	configMalformedMAC                = `{"eni":"eni1", "ipv4-address":"10.11.12.13", "mac":"01:23:45:67:89"}`
	validConfigWithIPV6               = `{
	"eni":"eni1",
	"ipv4-address":"10.11.12.13",
	"mac":"01:23:45:67:89:ab",
	"ipv6-address":"2001:db8::68"
}`
	validConfigWithAllFields = `{
	"eni":"eni1",
	"ipv4-address":"10.11.12.13",
	"mac":"01:23:45:67:89:ab",
	"ipv6-address":"2001:db8::68",
	"block-instance-metadata":true,
	"subnetgateway-ipv4-address":"10.11.0.1/24",
	"stay-down":true
}`
	configInvalidIPV6AddressMalformed = `{
	"eni":"eni1",
	"ipv4-address":"10.11.12.13",
	"mac":"01:23:45:67:89:ab",
	"ipv6-address":"2001:::68"
}`
	configInvalidIPV6AddressIPV4 = `{
	"eni":"eni1",
	"ipv4-address":"10.11.12.13",
	"mac":"01:23:45:67:89:ab",
	"ipv6-address":"10.11.12.13"
}`
)

func TestNewConfWithValidConfig(t *testing.T) {
	testCases := []struct {
		input string
		name  string
	}{
		{validConfigNoIPV6, "no ipv6"},
		{validConfigWithIPV6, "with ipv6"},
		{validConfigWithAllFields, "all fields"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args := &skel.CmdArgs{
				StdinData: []byte(tc.input),
			}
			_, err := NewConf(args)
			assert.NoError(t, err)
		})
	}
}

func TestNewConfWithInvalidConfig(t *testing.T) {
	testCases := []struct {
		input string
		name  string
	}{
		{`{"foo":"eni1"}`, "invalid keys"},
		{configNoENIID, "no eni id"},
		{configNoIPV4Address, "no ipv4 addr"},
		{configNoMAC, "no mac"},
		{configInvalidIPV4AddressMalformed, "malformed ipv4 addr"},
		{configInvalidIPV4AddressIPV6, "invalid ipv4 address"},
		{configMalformedMAC, "malformed mac"},
		{configInvalidIPV6AddressMalformed, "malformed ipv5 address"},
		{configInvalidIPV6AddressIPV4, "valid ipv4 malformed ipv6"},
		{"", "empty config"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args := &skel.CmdArgs{
				StdinData: []byte(tc.input),
			}
			_, err := NewConf(args)
			assert.Error(t, err)
		})
	}
}
