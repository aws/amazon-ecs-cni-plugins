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
	"os"

	"github.com/aws/amazon-ecs-cni-plugins/pkg/cniipamwrapper"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/cniipwrapper"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/netlinkwrapper"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

// configureVethContext wraps the parameters and the method to configure the
// veth interface in container's namespace
type configureVethContext struct {
	interfaceName               string
	result                      *current.Result
	ip                          cniipwrapper.IP
	ipam                        cniipamwrapper.IPAM
	netLink                     netlinkwrapper.NetLink
	connectedSubnetMaskSizeIPv4 int
	connectedSubnetMaskSizeIPv6 int
}

func newConfigureVethContext(interfaceName string,
	result *current.Result,
	ip cniipwrapper.IP,
	ipam cniipamwrapper.IPAM,
	netLink netlinkwrapper.NetLink,
	connectedSubnetMaskSizeIPv4 int,
	connectedSubnetMaskSizeIPv6 int) *configureVethContext {

	return &configureVethContext{
		interfaceName:               interfaceName,
		result:                      result,
		ip:                          ip,
		ipam:                        ipam,
		netLink:                     netLink,
		connectedSubnetMaskSizeIPv4: connectedSubnetMaskSizeIPv4,
		connectedSubnetMaskSizeIPv6: connectedSubnetMaskSizeIPv6,
	}
}

// run defines the closure to execute within the container's namespace to
// configure the veth interface
func (configContext *configureVethContext) run(hostNS ns.NetNS) error {
	// Get the link first so we can add gateway routes before ConfigureIface
	link, err := configContext.netLink.LinkByName(configContext.interfaceName)
	if err != nil {
		return errors.Wrapf(err,
			"bridge configure veth: unable to get link for interface: %s",
			configContext.interfaceName)
	}

	// Add gateway routes BEFORE ConfigureIface to make the gateway reachable
	// ConfigureIface needs the gateway to be reachable to add routes via it
	// Both daemon and awsvpc tasks use the same gateway route format:
	// "169.254.172.1 dev eth0 scope link"
	for _, ipConfig := range configContext.result.IPs {
		var maskBits int
		if ipConfig.Address.IP.To4() != nil {
			maskBits = 32
		} else {
			maskBits = 128
		}

		gatewayRoute := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst: &net.IPNet{
				IP:   ipConfig.Gateway,
				Mask: net.CIDRMask(maskBits, maskBits),
			},
			Scope: netlink.SCOPE_LINK,
		}

		err = configContext.netLink.RouteAdd(gatewayRoute)
		if err != nil && !os.IsExist(err) {
			return errors.Wrapf(err,
				"bridge configure veth: unable to add gateway route: %v", gatewayRoute)
		}
	}

	// Configure routes in the container (handles both IPv4 and IPv6)
	err = configContext.ipam.ConfigureIface(
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

	// link was already retrieved at the beginning of run()
	// Delete default routes and conditionally delete connected subnet routes based on caller's mask size parameter
	routes, err := configContext.netLink.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return errors.Wrapf(err,
			"bridge configure veth: unable to fetch routes for interface: %s",
			configContext.interfaceName)
	}

	// Delete default routes (0.0.0.0/0 or ::/0) and connected subnet routes when caller specifies mask size = 0
	for _, route := range routes {
		// Skip routes with a gateway
		if route.Gw != nil {
			continue
		}
		
		// Check if this is a default route
		isDefaultRoute := route.Dst == nil || 
			route.Dst.String() == "0.0.0.0/0" || 
			route.Dst.String() == "::/0"
		
		// Check if this is a connected subnet route that should be deleted based on caller's mask size parameter
		// Exclude /32 (IPv4) and /128 (IPv6) routes as these are host routes (like gateway routes)
		isConnectedSubnetToDelete := false
		if route.Dst != nil && !isDefaultRoute {
			maskSize, _ := route.Dst.Mask.Size()
			// If caller specified mask size = 0 for this IP version, delete non-host routes
			if route.Dst.IP.To4() != nil && configContext.connectedSubnetMaskSizeIPv4 == 0 && maskSize != 32 {
				isConnectedSubnetToDelete = true
			} else if route.Dst.IP.To4() == nil && configContext.connectedSubnetMaskSizeIPv6 == 0 && maskSize != 128 {
				isConnectedSubnetToDelete = true
			}
		}
		
		if isDefaultRoute || isConnectedSubnetToDelete {
			err = configContext.netLink.RouteDel(&route)
			if err != nil {
				return errors.Wrapf(err,
					"bridge configure veth: unable to delete route: %v", route)
			}
		}
	}

	// Explicitly add connected subnet route after cleanup
	// This route allows the container to reach other IPs in the same bridge subnet
	// Only add if caller specified non-zero connectedSubnetMaskSize (indicates daemon-bridge communication needed)
	for _, ipConfig := range configContext.result.IPs {
		// Skip if caller specified mask size = 0 (no daemon communication needed)
		if ipConfig.Address.IP.To4() != nil && configContext.connectedSubnetMaskSizeIPv4 == 0 {
			continue
		}
		if ipConfig.Address.IP.To4() == nil && configContext.connectedSubnetMaskSizeIPv6 == 0 {
			continue
		}
		
		// Determine the correct subnet mask size based on IP version
		var subnetMaskSize int
		var totalBits int
		if ipConfig.Address.IP.To4() != nil {
			subnetMaskSize = configContext.connectedSubnetMaskSizeIPv4
			totalBits = 32
		} else {
			subnetMaskSize = configContext.connectedSubnetMaskSizeIPv6
			totalBits = 128
		}
		
		// Create subnet mask using the connected subnet mask size
		subnetMask := net.CIDRMask(subnetMaskSize, totalBits)
		
		// Calculate the subnet network address using the connected subnet mask
		subnetIP := ipConfig.Address.IP.Mask(subnetMask)
		
		// Add the connected subnet route
		subnetRoute := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst: &net.IPNet{
				IP:   subnetIP,
				Mask: subnetMask,
			},
			Scope: netlink.SCOPE_LINK,
		}
		
		// Add the route, ignoring if it already exists
		err = configContext.netLink.RouteAdd(subnetRoute)
		if err != nil && !os.IsExist(err) {
			return errors.Wrapf(err,
				"bridge configure veth: unable to add connected subnet route: %v", subnetRoute)
		}
	}

	return nil
}
