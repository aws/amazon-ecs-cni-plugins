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

package config

import (
	"encoding/json"
	"net"

	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/pkg/errors"
)

// IPAMConfig represents the IP related network configuration
type IPAMConfig struct {
	types.CommonArgs
	Type      string         `json:"type,omitempty"`
	Subnet    types.IPNet    `json:"subnet,omitempty"`
	IPAddress types.IPNet    `json:"ipAddress,omitempty"`
	Gateway   net.IP         `json:"gateway,omitempty"`
	Routes    []*types.Route `json:"routes,omitempty"`
}

// Conf loads the option from configuration file
type Conf struct {
	Name       string      `json:"name,omitempty"`
	CNIVersion string      `json:"cniVersion,omitempty"`
	IPAM       *IPAMConfig `json:"ipam"`
}

// LoadIPAMConfig loads the IPAM configuration from the input bytes and validates the parameter
// bytes: Configuration read from os.stdin
// args: Configuration read from environment variable "CNI_ARGS"
func LoadIPAMConfig(bytes []byte, args string) (*current.Result, string, error) {
	conf := &Conf{}
	if err := json.Unmarshal(bytes, &conf); err != nil {
		return nil, "", errors.Wrapf(err, "failed to load netconf")
	}
	if conf.IPAM == nil {
		return nil, conf.CNIVersion, errors.New("IPAM field missing in configuration")
	}

	if err := types.LoadArgs(args, conf.IPAM); err != nil {
		return nil, conf.CNIVersion, errors.Wrapf(err, "failed to parse args: %v", args)
	}

	// convert from types.IPNet to net.IPNet
	subnet := net.IPNet{
		IP:   conf.IPAM.Subnet.IP,
		Mask: conf.IPAM.Subnet.Mask,
	}

	ipAddress := net.IPNet{
		IP:   conf.IPAM.IPAddress.IP,
		Mask: conf.IPAM.IPAddress.Mask,
	}

	// Check the ip address
	if ipAddress.IP == nil {
		return nil, "", errors.New("IPAddress is missing")
	}

	// check if the ip address is within the subnet
	if subnet.IP == nil || subnet.Mask == nil {
		if conf.IPAM.Gateway == nil {
			return nil, conf.CNIVersion, errors.New("gateway and subnet can't both be empty")
		}
	} else {
		err := validateSubnetIP(ipAddress.IP, subnet)
		if err != nil {
			return nil, conf.CNIVersion, err
		}

		// get the default gateway
		if conf.IPAM.Gateway == nil {
			conf.IPAM.Gateway = defaultGWFromSubnet(conf.IPAM.Subnet)
		}
	}

	var ipversion string
	if conf.IPAM.IPAddress.IP.To4() != nil {
		ipversion = "4"
	} else if conf.IPAM.IPAddress.IP.To16() != nil {
		ipversion = "6"
	} else {
		return nil, conf.CNIVersion, errors.New("invalid ip address")
	}

	ipConfig := &current.IPConfig{
		Version: ipversion,
		Address: ipAddress,
		Gateway: conf.IPAM.Gateway,
	}

	result := &current.Result{}
	result.IPs = []*current.IPConfig{ipConfig}
	result.Routes = conf.IPAM.Routes

	return result, conf.CNIVersion, nil
}

// validateSubnetIP check if the ip is within the subnet
func validateSubnetIP(ip net.IP, subnet net.IPNet) error {
	if !subnet.Contains(ip) {
		return errors.Errorf("ip %v is not within the subnet %v", ip, subnet)
	}

	return nil
}

// defaultGWFromSubnet returns the first ip address in the subnet as the gateway
func defaultGWFromSubnet(subnet types.IPNet) net.IP {
	return ip.NextIP(subnet.IP)
}
