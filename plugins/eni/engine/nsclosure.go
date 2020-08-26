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
	"fmt"
	"net"
	"syscall"

	"github.com/aws/amazon-ecs-cni-plugins/pkg/netlinkwrapper"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

const (
	instanceMetadataEndpoint = "169.254.169.254/32"
)

var linkWithMACNotFoundError = errors.New("engine: device with mac address not found")

// setupNamespaceClosureContext wraps the parameters and the method to configure the container's namespace
type setupNamespaceClosureContext struct {
	netLink      netlinkwrapper.NetLink
	ifName       string
	deviceName   string
	macAddress   string
	ipAddrs      []*netlink.Addr
	gatewayAddrs []net.IP
	blockIMDS    bool
	mtu          int
}

// teardownNamespaceClosureContext wraps the parameters and the method to teardown the
// container's namespace
type teardownNamespaceClosureContext struct {
	netLink      netlinkwrapper.NetLink
	hardwareAddr net.HardwareAddr
}

// newSetupNamespaceClosureContext creates a new setupNamespaceClosure object
func newSetupNamespaceClosureContext(
	netLink netlinkwrapper.NetLink,
	ifName string,
	deviceName string,
	macAddress string,
	ipAddresses []string,
	gatewayAddresses []string,
	blockIMDS bool,
	mtu int) (*setupNamespaceClosureContext, error) {

	nsClosure := &setupNamespaceClosureContext{
		netLink:    netLink,
		ifName:     ifName,
		deviceName: deviceName,
		macAddress: macAddress,
		blockIMDS:  blockIMDS,
		mtu:        mtu,
	}

	for _, addr := range ipAddresses {
		nlIPAddr, err := netLink.ParseAddr(addr)
		if err != nil {
			return nil, errors.Wrapf(err,
				"setupNamespaceClosure engine: unable to parse ip address '%s' for the interface", addr)
		}
		nsClosure.ipAddrs = append(nsClosure.ipAddrs, nlIPAddr)
	}

	for _, addr := range gatewayAddresses {
		gatewayAddr := net.ParseIP(addr)
		if gatewayAddr == nil {
			return nil, fmt.Errorf(
				"setupNamespaceClosure engine: unable to parse gateway ip address '%s'", addr)
		}
		nsClosure.gatewayAddrs = append(nsClosure.gatewayAddrs, gatewayAddr)
	}

	return nsClosure, nil
}

// newTeardownNamespaceClosureContext creates a new teardownNamespaceClosure object
func newTeardownNamespaceClosureContext(netLink netlinkwrapper.NetLink,
	mac string) (*teardownNamespaceClosureContext, error) {
	hardwareAddr, err := net.ParseMAC(mac)
	if err != nil {
		return nil, errors.Wrapf(err,
			"newTeardownNamespaceClosure engine: malformatted mac address specified")
	}

	return &teardownNamespaceClosureContext{
		netLink:      netLink,
		hardwareAddr: hardwareAddr,
	}, nil
}

// run defines the closure to execute within the container's namespace to configure it
// appropriately
func (closureContext *setupNamespaceClosureContext) run(_ ns.NetNS) error {
	// Get the link for the ENI device
	eniLink, err := closureContext.netLink.LinkByName(closureContext.deviceName)
	if err != nil {
		return errors.Wrapf(err,
			"setupNamespaceClosure engine: unable to get link for device '%s'",
			closureContext.deviceName)
	}

	err = closureContext.netLink.LinkSetName(eniLink, closureContext.ifName)
	if err != nil {
		return errors.Wrap(err, "setupNamespaceClosure engine: unable to change interface name")
	}

	// Add IP addresses to the link
	for _, addr := range closureContext.ipAddrs {
		err = closureContext.netLink.AddrAdd(eniLink, addr)
		if err != nil {
			return errors.Wrap(err,
				"setupNamespaceClosure engine: unable to add ip address to the interface")
		}
	}

	// Bring it up
	err = closureContext.netLink.LinkSetUp(eniLink)
	if err != nil {
		return errors.Wrap(err,
			"setupNamespaceClosure engine: unable to bring up the device")
	}

	// Change the MTU if it is customized
	if closureContext.mtu != 0 {
		err = closureContext.netLink.LinkSetMTU(eniLink, closureContext.mtu)
		if err != nil {
			return errors.Wrap(err, "setupNamespaceClosure engine: unable to set mtu of interface")
		}
	}

	// Add a blackhole route for IMDS endpoint if required
	if closureContext.blockIMDS {
		_, imdsNetwork, err := net.ParseCIDR(instanceMetadataEndpoint)
		if err != nil {
			// This should never happen because we always expect
			// 169.254.169.254/32 to be parsed without any errors
			return errors.Wrapf(err, "setupNamespaceClosure engine: unable to parse instance metadata endpoint")
		}
		if err = closureContext.netLink.RouteAdd(&netlink.Route{
			Dst:  imdsNetwork,
			Type: syscall.RTN_BLACKHOLE,
		}); err != nil {
			return errors.Wrapf(err, "setupNamespaceClosure engine: unable to add route to block instance metadata")
		}
	}

	// Setup IP routes for the gateways
	for _, gwAddr := range closureContext.gatewayAddrs {
		err = closureContext.netLink.RouteAdd(&netlink.Route{
			LinkIndex: eniLink.Attrs().Index,
			Gw:        gwAddr,
		})
		if err != nil && !isRouteExistsError(err) {
			return errors.Wrap(err,
				"setupNamespaceClosure engine: unable to add the route for the gateway")
		}
	}

	return nil
}

// isRouteExistsError returns true if the error type is syscall.EEXIST
// This helps us determine if we should ignore this error as the route
// that we want to add already exists in the routing table
func isRouteExistsError(err error) bool {
	if errno, ok := err.(syscall.Errno); ok {
		return errno == syscall.EEXIST
	}

	return false
}

// run defines the closure to execute within the container's namespace to tear it down
func (closureContext *teardownNamespaceClosureContext) run(_ ns.NetNS) error {
	return nil
}

// getLinkByHardwareAddress gets the link device based on the mac address
func getLinkByHardwareAddress(netLink netlinkwrapper.NetLink, hardwareAddr net.HardwareAddr) (netlink.Link, error) {
	links, err := netLink.LinkList()
	if err != nil {
		return nil, err
	}

	for _, link := range links {
		// TODO: Evaluate if reflect.DeepEqual is a better alternative here
		if link.Attrs().HardwareAddr.String() == hardwareAddr.String() {
			return link, nil
		}
	}

	return nil, linkWithMACNotFoundError
}
