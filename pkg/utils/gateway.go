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
	"fmt"
	"net"

	"github.com/pkg/errors"
)

const (
	minIPV4CIDRBlockSize = 28
	maxIPV4CIDRBlockSize = 16
)

// ParseIPV4GatewayNetmaskError is used to indicate any error with parsing the
// IPV4 address and the netmask of the ENI
type ParseIPV4GatewayNetmaskError struct {
	operation string
	origin    string
	message   string
}

func (err *ParseIPV4GatewayNetmaskError) Error() string {
	return err.operation + " " + err.origin + ": " + err.message
}

func newParseIPV4GatewayNetmaskError(operation string, origin string, message string) error {
	return &ParseIPV4GatewayNetmaskError{
		operation: operation,
		origin:    origin,
		message:   message,
	}
}

// ComputeIPV4GatewayNetmask computes the subnet gateway and netmask for
// the gateway given the ipv4 cidr block for the ENI
// Gateways are provided in VPC subnets at base +1
// (NOTE: from the base of the subnet, not the VPC base)
// https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Subnets.html#vpc-sizing-ipv4
func ComputeIPV4GatewayNetmask(cidrBlock string) (string, string, error) {
	// The IPV4 CIDR block is of the format ip-addr/netmask
	ip, ipNet, err := net.ParseCIDR(cidrBlock)
	if err != nil {
		return "", "", errors.Wrapf(err,
			"compute ipv4 gateway netmask: unable to parse cidr: '%s'", cidrBlock)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return "", "", newParseIPV4GatewayNetmaskError("compute ipv4 gateway netmask", "engine",
			fmt.Sprintf("unable to parse ipv4 gateway from cidr block '%s'", cidrBlock))
	}

	maskOnes, _ := ipNet.Mask.Size()
	// As per
	// http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Subnets.html#VPC_Sizing
	// You can assign a single CIDR block to a VPC. The allowed block size
	// is between a /16 netmask and /28 netmask. Verify that
	if maskOnes > minIPV4CIDRBlockSize {
		return "", "", errors.Errorf("compute ipv4 gateway netmask: invalid ipv4 cidr block, %d > 28", maskOnes)
	}
	if maskOnes < maxIPV4CIDRBlockSize {
		return "", "", errors.Errorf("compute ipv4 gateway netmask: invalid ipv4 cidr block, %d <= 16", maskOnes)
	}

	// ipv4 gateway is the first available IP address in the subnet
	ip4[3] = ip4[3] + 1
	return ip4.String(), fmt.Sprintf("%d", maskOnes), nil
}

// ParseIPV4GatewayNetmask parses the cidr block to return the subnet gateway
// ip and the netmask. There's no additional computation here. It essentially
// splits the string on '/' and returns the parts. However, it uses golang's
// 'net' package to do this. It also performs additional validation of the
// cidr block, which is typically passed to the plugin as a config
func ParseIPV4GatewayNetmask(cidrBlock string) (string, string, error) {
	// The IPV4 CIDR block is of the format ip-addr/netmask
	ip, ipNet, err := net.ParseCIDR(cidrBlock)
	if err != nil {
		return "", "", errors.Wrapf(err,
			"parse ipv4 gateway netmask: unable to parse ipv4 subnet gateway from config: '%s'", cidrBlock)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return "", "", errors.Errorf("parse ipv4 gateway netmask: unable to parse ipv4 gateway from config: '%s'",
			cidrBlock)
	}

	maskOnes, _ := ipNet.Mask.Size()
	// As per
	// http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Subnets.html#VPC_Sizing
	// You can assign a single CIDR block to a VPC. The allowed block size
	// is between a /16 netmask and /28 netmask. Verify that
	if maskOnes > minIPV4CIDRBlockSize {
		return "", "", errors.Errorf("parse ipv4 gateway netmask: invalid ipv4 cidr block, %d > 28", maskOnes)
	}
	if maskOnes < maxIPV4CIDRBlockSize {
		return "", "", errors.Errorf("parse ipv4 gateway netmask: invalid ipv4 cidr block, %d <= 16", maskOnes)
	}

	return ip4.String(), fmt.Sprintf("%d", maskOnes), nil
}
