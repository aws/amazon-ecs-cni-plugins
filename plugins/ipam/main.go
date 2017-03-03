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
	"net"

	"github.com/aws/amazon-ecs-cni-plugins/pkg/version"
	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/pkg/errors"
)

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.GetPluginVersionSupported())
}

// cmdAdd will return ip, gateway, routes which can be
// used in bridge plugin to configure veth pair and bridge
func cmdAdd(args *skel.CmdArgs) error {
	conf, cniVersion, err := LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	// convert from types.IPNet to net.IPNet
	subnet := net.IPNet{
		IP:   conf.Subnet.IP,
		Mask: conf.Subnet.Mask,
	}

	ipAddress := net.IPNet{
		IP:   conf.IPAddres.IP,
		Mask: conf.IPAddres.Mask,
	}

	// Check the ip address
	if ipAddress.IP == nil {
		return errors.New("IPAddress is missing")
	}

	// check if the ip address is within the subnet
	if subnet.IP == nil || subnet.Mask == nil {
		if conf.Gateway == nil {
			return errors.New("gateway and subnet can't both be empty")
		}
	} else {
		err = validateSubnetIP(ipAddress.IP, subnet)
		if err != nil {
			return err
		}

		// get the default gateway
		if conf.Gateway == nil {
			conf.Gateway = getGatewayFromSubnet(conf.Subnet)
		}
	}

	result := &current.Result{}

	var ipversion string
	if conf.IPAddres.IP.To4() != nil {
		ipversion = "4"
	} else if conf.IPAddres.IP.To16() != nil {
		ipversion = "6"
	} else {
		return errors.New("invalid ip address")
	}
	ipConfig := &current.IPConfig{
		Version: ipversion,
		Address: ipAddress,
		Gateway: conf.Gateway,
	}

	result.IPs = []*current.IPConfig{ipConfig}
	result.Routes = conf.Routes

	return types.PrintResult(result, cniVersion)
}

// cmdDel won't be used, so just return
func cmdDel(args *skel.CmdArgs) error {
	return nil
}

// validateSubnetIP check if the ip is within the subnet
func validateSubnetIP(ip net.IP, subnet net.IPNet) error {
	if !subnet.Contains(ip) {
		return errors.Errorf("ip %v is not within the subnet %v", ip, subnet)
	}

	return nil
}

// getGatewayFromSubnet returns the first ip address in the subnet as the gateway
func getGatewayFromSubnet(subnet types.IPNet) net.IP {
	return ip.NextIP(subnet.IP)
}
