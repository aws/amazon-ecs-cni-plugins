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
	"strconv"
	"strings"

	"github.com/aws/amazon-ecs-cni-plugins/pkg/execwrapper"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/ioutilwrapper"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/netlinkwrapper"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/oswrapper"
	log "github.com/cihub/seelog"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

const (
	dhclientExecutableName = "dhclient"
	// TODO: These paths should probably not be /var/lib/dhclient or
	// /var/run/. Instead these should go into their own subdirs.
	// Example: /var/lib/dhclient/ns/ and /var/run/ns/
	// It's more helpful when debugging to have it set that way. We
	// expect the Agent to create those directories. We can also let
	// these be configured via the plugin config.
	dhclientV4LeaseFilePathPrefix    = "/var/lib/dhclient/ns-dhclient4"
	dhclientV4LeasePIDFilePathPrefix = "/var/run/ns-dhclient4"
	dhclientV6LeaseFilePathPrefix    = "/var/lib/dhclient/ns-dhclient6"
	dhclientV6LeasePIDFilePathPrefix = "/var/run/ns-dhclient6"
)

var linkWithMACNotFoundError = errors.Errorf("engine: device with mac address not found")

// setupNamespaceClosureContext wraps the parameters and the method to configure the container's namespace
type setupNamespaceClosureContext struct {
	netLink     netlinkwrapper.NetLink
	exec        execwrapper.Exec
	deviceName  string
	ipv4Addr    *netlink.Addr
	ipv6Addr    *netlink.Addr
	ipv4Gateway net.IP
	ipv6Gateway net.IP
}

// teardownNamespaceClosureContext wraps the parameters and the method to teardown the
// container's namespace
type teardownNamespaceClosureContext struct {
	netLink       netlinkwrapper.NetLink
	ioutil        ioutilwrapper.IOUtil
	os            oswrapper.OS
	hardwareAddr  net.HardwareAddr
	stopDHClient6 bool
}

// newSetupNamespaceClosureContext creates a new setupNamespaceClosure object
func newSetupNamespaceClosureContext(netLink netlinkwrapper.NetLink, exec execwrapper.Exec, deviceName string, ipv4Address string, ipv6Address string, ipv4Gateway string, ipv6Gateway string) (*setupNamespaceClosureContext, error) {
	nlIPV4Addr, err := netLink.ParseAddr(ipv4Address)
	if err != nil {
		return nil, errors.Wrap(err, "setupNamespaceClosure engine: unable to parse ipv4 address for the interface")
	}

	ipv4GatewayIP := net.ParseIP(ipv4Gateway)
	if ipv4GatewayIP == nil {
		return nil, errors.New("setupNamespaceClosure engine: unable to parse address of the ipv4 gateway")
	}

	nsClosure := &setupNamespaceClosureContext{
		netLink:     netLink,
		exec:        exec,
		deviceName:  deviceName,
		ipv4Addr:    nlIPV4Addr,
		ipv4Gateway: ipv4GatewayIP,
	}
	if ipv6Address != "" {
		nlIPV6Addr, err := netLink.ParseAddr(ipv6Address)
		if err != nil {
			return nil, errors.Wrap(err, "setupNamespaceClosure engine: unable to parse ipv6 address for the interface")
		}
		ipv6GatewayIP := net.ParseIP(ipv6Gateway)
		if ipv6GatewayIP == nil {
			return nil, errors.New("setupNamespaceClosure engine: unable to parse address of the ipv6 gateway")
		}
		nsClosure.ipv6Addr = nlIPV6Addr
		nsClosure.ipv6Gateway = ipv6GatewayIP
	}

	return nsClosure, nil
}

// newTeardownNamespaceClosureContext creates a new teardownNamespaceClosure object
func newTeardownNamespaceClosureContext(netLink netlinkwrapper.NetLink, ioutil ioutilwrapper.IOUtil, os oswrapper.OS, mac string, stopDHClient6 bool) (*teardownNamespaceClosureContext, error) {
	hardwareAddr, err := net.ParseMAC(mac)
	if err != nil {
		return nil, errors.Wrapf(err, "newTeardownNamespaceClosure engine: malformatted mac address specified")
	}

	return &teardownNamespaceClosureContext{
		netLink:       netLink,
		ioutil:        ioutil,
		os:            os,
		hardwareAddr:  hardwareAddr,
		stopDHClient6: stopDHClient6,
	}, nil
}

// run defines the closure to execute within the container's namespace to configure it
// appropriately
func (closureContext *setupNamespaceClosureContext) run(_ ns.NetNS) error {
	// Get the link for the ENI device
	eniLink, err := closureContext.netLink.LinkByName(closureContext.deviceName)
	if err != nil {
		return errors.Wrapf(err,
			"setupNamespaceClosure engine: unable to get link for device '%s'", closureContext.deviceName)
	}

	// Add the IPV4 Address to the link
	err = closureContext.netLink.AddrAdd(eniLink, closureContext.ipv4Addr)
	if err != nil {
		return errors.Wrap(err, "setupNamespaceClosure engine: unable to add ipv4 address to the interface")
	}

	if closureContext.ipv6Addr != nil {
		// Add the IPV6 Address to the link
		err = closureContext.netLink.AddrAdd(eniLink, closureContext.ipv6Addr)
		if err != nil {
			return errors.Wrap(err, "setupNamespaceClosure engine: unable to add ipv6 address to the interface")
		}
	}

	// Bring it up
	err = closureContext.netLink.LinkSetUp(eniLink)
	if err != nil {
		return errors.Wrap(err, "setupNamespaceClosure engine: unable to bring up the device")
	}

	// Setup ipv4 route for the gateway
	err = closureContext.netLink.RouteAdd(&netlink.Route{Gw: closureContext.ipv4Gateway})
	if err != nil {
		return errors.Wrap(err, "setupNamespaceClosure engine: unable to add the route for the ipv4 gateway")
	}

	// Start dhclient for IPV4 address
	err = closureContext.startDHClientV4()
	if err != nil {
		return err
	}

	if closureContext.ipv6Addr != nil {
		// Setup ipv6 route for the gateway
		err = closureContext.netLink.RouteAdd(&netlink.Route{Gw: closureContext.ipv6Gateway})
		if err != nil {
			return errors.Wrap(err, "setupNamespaceClosure engine: unable to add the route for the ipv6 gateway")
		}

		// Start dhclient for IPV6 address
		err = closureContext.startDHClientV6()
		if err != nil {
			return err
		}
	}

	return nil
}

// startDHClientV4 starts the dhclient with arguments to renew the lease on the IPV4 address
// of the ENI
func (closureContext *setupNamespaceClosureContext) startDHClientV4() error {
	args := constructDHClientV4Args(closureContext.deviceName)
	cmd := closureContext.exec.Command(dhclientExecutableName, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Errorf("Error executing '%s' with args '%v': raw output: %s",
			dhclientExecutableName, args, string(out))
		return errors.Wrapf(err,
			"setupNamespaceClosure engine: unable to start dhclient for ipv4 address; command: %s %v; output: %s",
			dhclientExecutableName, args, string(out))
	}

	return nil
}

// constructDHClientV4Args constructs the arguments list for the dhclient command to
// renew the lease on the IPV4 address
func constructDHClientV4Args(deviceName string) []string {
	return []string{
		"-q",
		"-lf", dhclientV4LeaseFilePathPrefix + "-" + deviceName + ".leases",
		"-pf", constructDHClientLeasePIDFilePathIPV4(deviceName),
		deviceName,
	}
}

// constructDHClientLeasePIDFilePathIPV4 constructs the PID file path for the dhclient
// process that's renewing the IPV4 address lease for the ENI device
func constructDHClientLeasePIDFilePathIPV4(deviceName string) string {
	return dhclientV4LeasePIDFilePathPrefix + "-" + deviceName + ".pid"
}

// startDHClientV6 starts the dhclient with arguments to renew the lease on the IPV6 address
// of the ENI
func (closureContext *setupNamespaceClosureContext) startDHClientV6() error {
	args := constructDHClientV6Args(closureContext.deviceName)
	cmd := closureContext.exec.Command(dhclientExecutableName, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Errorf("Error executing '%s' with args '%v': raw output: %s",
			dhclientExecutableName, args, string(out))
		return errors.Wrapf(err,
			"setupNamespaceClosure engine: unable to start dhclient for ipv6 address; command: %s %v; output: %s",
			dhclientExecutableName, args, string(out))
	}

	return nil
}

// constructDHClientV6Args constructs the arguments list for the dhclient command to
// renew the lease on the IPV6 address
func constructDHClientV6Args(deviceName string) []string {
	return []string{
		"-q",
		"-6",
		"-lf", dhclientV6LeaseFilePathPrefix + "-" + deviceName + ".leases",
		"-pf", constructDHClientLeasePIDFilePathIPV6(deviceName),
		deviceName,
	}
}

// constructDHClientLeasePIDFilePathIPV6 constructs the PID file path for the dhclient
// process that's renewing the IPV6 address lease for the ENI device
func constructDHClientLeasePIDFilePathIPV6(deviceName string) string {
	return dhclientV6LeasePIDFilePathPrefix + "-" + deviceName + ".pid"
}

// run defines the closure to execute within the container's namespace to tear it down
func (closureContext *teardownNamespaceClosureContext) run(_ ns.NetNS) error {
	link, err := getLinkByHardwareAddress(closureContext.netLink, closureContext.hardwareAddr)
	if err != nil {
		return errors.Wrapf(err,
			"teardownNamespaceClosure engine: unable to get device with hardware address '%s'", closure.hardwareAddr.String())
	}

	deviceName := link.Attrs().Name
	log.Debugf("Found link device as: %s", deviceName)

	// Stop the dhclient process for IPV4 address
	err = closureContext.stopDHClient(constructDHClientLeasePIDFilePathIPV4(deviceName))
	if err != nil {
		return err
	}

	if closureContext.stopDHClient6 {
		// Stop the dhclient process for IPV6 address
		err = closureContext.stopDHClient(constructDHClientLeasePIDFilePathIPV6(deviceName))
		if err != nil {
			return err
		}
	}

	log.Infof("Cleaned up dhclient")
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

func (closureContext *teardownNamespaceClosureContext) stopDHClient(pidFilePath string) error {
	// Extract the PID of the dhclient process
	contents, err := closureContext.ioutil.ReadFile(pidFilePath)
	if err != nil {
		return errors.Wrapf(err,
			"teardownNamespaceClosure engine: error reading dhclient pid from '%s'", pidFilePath)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(contents)))
	if err != nil {
		return errors.Wrapf(err,
			"teardownNamespaceClosure engine: error parsing dhclient pid from '%s'", pidFilePath)
	}
	process, err := closureContext.os.FindProcess(pid)
	if err != nil {
		return errors.Wrapf(err,
			"teardownNamespaceClosure engine: error getting process handle for dhclient, pid file: '%s'", pidFilePath)
	}

	// Stop the dhclient process
	err = process.Kill()
	if err != nil {
		return errors.Wrapf(err,
			"teardownNamespaceClosure engine: error stopping the dhclient process, pid file: '%s'", pidFilePath)
	}

	return nil
}
