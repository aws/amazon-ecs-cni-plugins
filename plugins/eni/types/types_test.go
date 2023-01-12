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

package types

import (
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/stretchr/testify/assert"
)

var (
	// Invalid configs.
	configNoENIID                     = `{"ip-addresses":["10.11.12.13/16"], "mac":"01:23:45:67:89:ab"}`
	configNoIPAddresses               = `{"eni":"eni1", "mac":"01:23:45:67:89:ab"}`
	configNoMAC                       = `{"eni":"eni1", "ip-addresses":["10.11.12.13/16"]}`
	configInvalidIPv4AddressMalformed = `{"eni":"eni1", "ip-addresses":["1"], "mac":"01:23:45:67:89:ab"}`
	configInvalidIPv6AddressMalformed = `{"eni":"eni1", "ip-addresses":["2001:::68/64"], "mac":"01:23:45:67:89:ab"}`
	configInvalidMultiAddrsMalformed  = `{"eni":"eni1", "ip-addresses":["10.11.12.13","2001:::68/64"], "mac":"01:23:45:67:89:ab"}`
	configMalformedMAC                = `{"eni":"eni1", "ip-addresses":["10.11.12.13/16"], "mac":"01:23:45:67:89"}`

	// Valid configs.
	validConfigWithIPv4      = `{"eni":"eni1", "ip-addresses":["10.11.12.13/16"], "mac":"01:23:45:67:89:ab"}`
	validConfigWithIPv6      = `{"eni":"eni1",	"ip-addresses":["2001:db8::68/64"], "mac":"01:23:45:67:89:ab"}`
	validConfigWithAllFields = `{
	"eni":"eni1",
	"ip-addresses":["10.11.12.13/16","2001:db8::68/64"],
	"mac":"01:23:45:67:89:ab",
	"block-instance-metadata":true,
	"gateway-ip-addresses":["10.11.0.1", "fe80:1234::abcd:ef01"],
	"stay-down":true
}`
)

func TestNewConfWithValidConfig(t *testing.T) {
	testCases := []struct {
		input string
		name  string
	}{
		{validConfigWithIPv4, "with ipv4"},
		{validConfigWithIPv6, "with ipv6"},
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
		{configNoIPAddresses, "no ip addr"},
		{configNoMAC, "no mac"},
		{configInvalidIPv4AddressMalformed, "malformed ipv4 addr"},
		{configInvalidIPv6AddressMalformed, "malformed ipv6 address"},
		{configInvalidMultiAddrsMalformed, "multiple IP addresses some invalid"},
		{configMalformedMAC, "malformed mac"},
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
