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

package engine

import (
	"net"

	"github.com/aws/amazon-ecs-cni-plugins/pkg/cniipamwrapper"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/cniipwrapper"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/netlinkwrapper"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

// configureVethContext wraps the parameters and the method to configure the
// veth interface in container's namespace
type configureVethContext struct {
	interfaceName string
	result        *current.Result
	ip            cniipwrapper.IP
	ipam          cniipamwrapper.IPAM
	netLink       netlinkwrapper.NetLink
}

func newConfigureVethContext(interfaceName string,
	result *current.Result,
	ip cniipwrapper.IP,
	ipam cniipamwrapper.IPAM,
	netLink netlinkwrapper.NetLink) *configureVethContext {

	return &configureVethContext{
		interfaceName: interfaceName,
		result:        result,
		ip:            ip,
		ipam:          ipam,
		netLink:       netLink,
	}
}

// run defines the closure to execute within the container's namespace to
// configure the veth interface
func (configContext *configureVethContext) run(hostNS ns.NetNS) error {
	// Add gateway routes for each IP configuration BEFORE ConfigureIface
	// For IPv4: /32 route for ARP query request from host
	// For IPv6: /128 route for neighbor discovery
	// These routes have an explicit gateway set to the gateway IP itself,
	// which ConfigureIface will use when adding the route.
	for _, ipConfig := range configContext.result.IPs {
		var maskBits int
		if ipConfig.Address.IP.To4() != nil {
			maskBits = 32 // IPv4: /32 for gateway route
		} else {
			maskBits = 128 // IPv6: /128 for gateway route
		}

		route := &types.Route{
			Dst: net.IPNet{
				IP:   ipConfig.Gateway,
				Mask: net.CIDRMask(maskBits, maskBits),
			},
			// Set explicit gateway so ConfigureIface uses it
			GW: ipConfig.Gateway,
		}
		configContext.result.Routes = append(configContext.result.Routes, route)
	}

	// Configure routes in the container (handles both IPv4 and IPv6)
	err := configContext.ipam.ConfigureIface(
		configContext.interfaceName, configContext.result)
	if err != nil {
		return errors.Wrapf(err,
			"bridge configure veth: unable to configure interface: %s",
			configContext.interfaceName)
	}

	// Set hardware address based on available IP addresses
	// SetHWAddrByIP takes separate IPv4 and IPv6 parameters
	var hwAddrIPv4, hwAddrIPv6 net.IP
	for _, ipConfig := range configContext.result.IPs {
		if ipConfig.Address.IP.To4() != nil {
			if hwAddrIPv4 == nil {
				hwAddrIPv4 = ipConfig.Address.IP
			}
		} else {
			if hwAddrIPv6 == nil {
				hwAddrIPv6 = ipConfig.Address.IP
			}
		}
	}

	// Only call SetHWAddrByIP if we have at least one IP address
	if hwAddrIPv4 != nil || hwAddrIPv6 != nil {
		err = configContext.ip.SetHWAddrByIP(
			configContext.interfaceName, hwAddrIPv4, hwAddrIPv6)
		if err != nil {
			return errors.Wrapf(err,
				"bridge configure veth: unable to set hardware address for interface: %s",
				configContext.interfaceName)
		}
	}

	link, err := configContext.netLink.LinkByName(configContext.interfaceName)
	if err != nil {
		return errors.Wrapf(err,
			"bridge configure veth: unable to get link for interface: %s",
			configContext.interfaceName)
	}

	// Delete default routes for ALL address families (both IPv4 and IPv6)
	routes, err := configContext.netLink.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return errors.Wrapf(err,
			"bridge configure veth: unable to fetch routes for interface: %s",
			configContext.interfaceName)
	}

	// Delete all default routes within the container (routes without a gateway)
	// Routes with a gateway (including our gateway routes) will be preserved
	for _, route := range routes {
		if route.Gw == nil {
			err = configContext.netLink.RouteDel(&route)
			if err != nil {
				return errors.Wrapf(err,
					"bridge configure veth: unable to delete route: %v", route)
			}
		}
	}

	return nil
}
