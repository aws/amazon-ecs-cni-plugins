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
	"crypto/rand"
	"net"
	"strings"
	"syscall"

	log "github.com/cihub/seelog"

	"github.com/aws/amazon-ecs-cni-plugins/pkg/cniipamwrapper"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/cniipwrapper"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/cninswrapper"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/netlinkwrapper"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

const (
	// zeroLengthIPString is what we expect net.IP.String() to return if the
	// ip has length 0. We use this to determing if an IP is empty.
	// Refer https://golang.org/pkg/net/#IP.String
	zeroLengthIPString = "<nil>"

	fileExistsErrMsg = "file exists"
)

// Engine represents the execution engine for the ECS Bridge plugin.
// It defines all the operations performed during the execution of the
// plugin
type Engine interface {
	CreateBridge(bridgeName string, mtu int) (*netlink.Bridge, error)
	CreateVethPair(netnsName string, mtu int, interfaceName string) (*current.Interface, string, error)
	AttachHostVethInterfaceToBridge(hostVethName string, bridge *netlink.Bridge) (*current.Interface, error)
	RunIPAMPluginAdd(plugin string, netConf []byte) (*current.Result, error)
	ConfigureContainerVethInterface(netnsName string, result *current.Result, interfaceName string) error
	ConfigureBridge(result *current.Result, bridge *netlink.Bridge) error
	GetInterfaceIPV4Address(netnsName string, interfaceName string) (string, error)
	RunIPAMPluginDel(plugin string, netconf []byte) error
	DeleteVeth(netnsName string, interfaceName string) error
}

type engine struct {
	netLink netlinkwrapper.NetLink
	ns      cninswrapper.NS
	ip      cniipwrapper.IP
	ipam    cniipamwrapper.IPAM
}

// New creates a new Engine object
func New() Engine {
	return &engine{
		netLink: netlinkwrapper.NewNetLink(),
		ns:      cninswrapper.NewNS(),
		ip:      cniipwrapper.New(),
		ipam:    cniipamwrapper.New(),
	}
}

// CreateBridge creates the bridge if needed
func (engine *engine) CreateBridge(bridgeName string, mtu int) (*netlink.Bridge, error) {
	bridge, err := engine.lookupBridge(bridgeName)
	if err != nil {
		return nil, err
	}

	if bridge == nil {
		err = engine.createBridge(bridgeName, mtu)
		if err != nil {
			if !strings.Contains(err.Error(), fileExistsErrMsg) {
				return nil, err
			}
			// If the error returned by createBridge is that the bridge already exists, proceed to
			// lookupBridge because that means the bridge was created by someone else right before
			// we tried creating it, which is fine
		}

		// We need to lookup the bridge link again because LinkAdd
		// doesn't return a handle to the link with all the other
		// attributes set
		bridge, err = engine.lookupBridge(bridgeName)
		if err != nil {
			return nil, err
		}
	}

	if err := engine.netLink.LinkSetUp(bridge); err != nil {
		return nil, errors.Wrapf(err,
			"bridge create: unable to bring up the bridge interface %s", bridgeName)
	}

	return bridge, nil
}

// lookupBridge tries to get the link interface for the bridge by its name. If
// it cannot find the bridge it returns nil. If the link device is not of type
// bridge, or if there's an error with LinkByName, it returns an error
func (engine *engine) lookupBridge(bridgeName string) (*netlink.Bridge, error) {
	bridgeLink, err := engine.netLink.LinkByName(bridgeName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); !ok {
			return nil, errors.Wrapf(err,
				"bridge create: error lookup the bridge interface %s", bridgeName)
		}

		return nil, nil
	}

	bridge, ok := bridgeLink.(*netlink.Bridge)
	if !ok {
		return nil, errors.Errorf(
			"bridge create: interface named %s already exists, but is not a bridge",
			bridgeName)
	}

	return bridge, nil
}

// generateMACAddress generates a random locally-administrated MAC address.
func (engine *engine) generateMACAddress() (net.HardwareAddr, error) {
	buf := make([]byte, 6)
	var mac net.HardwareAddr

	_, err := rand.Read(buf)
	if err != nil {
		return mac, err
	}

	// Set locally administered addresses bit and reset multicast bit
	buf[0] = (buf[0] | 0x02) & 0xfe
	mac = append(mac, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])
	return mac, nil
}

// createBridge creates a bridge interface
func (engine *engine) createBridge(bridgeName string, mtu int) error {
	bridgeLinkAttributes := netlink.NewLinkAttrs()
	bridgeLinkAttributes.MTU = mtu
	bridgeLinkAttributes.Name = bridgeName

	bridge := &netlink.Bridge{
		LinkAttrs: bridgeLinkAttributes,
	}

	err := engine.netLink.LinkAdd(bridge)
	if err != nil {
		return errors.Wrapf(err,
			"bridge create: unable to add bridge interface %s", bridgeName)
	}

	// Bridge by default inherits the lowest of the MAC addresses of interfaces connected to its ports.
	// As interfaces connect and disconnect, the bridge MAC address changes dynamically, causing the
	// corresponding ARP cache entry in container network namespaces to become stale, which results
	// in brief periods of lost network connectivity as containers learn the new bridge MAC address.
	// Explicitly setting a static MAC address solves this problem.
	mac, err := engine.generateMACAddress()
	if err != nil {
		return errors.Wrapf(err,
			"bridge create: unable to generate mac addr %s", err)
	}

	log.Infof("Setting ecs-bridge hardware addr (MAC) %v", mac)
	err = engine.netLink.LinkSetHardwareAddr(bridge, mac)
	if err != nil {
		return errors.Wrapf(err,
			"bridge create: unable to set bridge MAC address %s up", bridgeName)
	}

	return nil
}

// CreateVethPair creates the veth pair to attach the container to the bridge
func (engine *engine) CreateVethPair(netnsName string, mtu int, interfaceName string) (*current.Interface, string, error) {
	createVethContext := newCreateVethPairContext(
		interfaceName, mtu, engine.ip)

	err := engine.ns.WithNetNSPath(netnsName, createVethContext.run)

	if err != nil {
		return nil, "", err
	}

	return createVethContext.containerInterfaceResult, createVethContext.hostVethName, nil
}

// AttachHostVethInterfaceToBridge moves the host end of the veth pair to the bridge
func (engine *engine) AttachHostVethInterfaceToBridge(hostVethName string, bridge *netlink.Bridge) (*current.Interface, error) {
	hostVethInterface, err := engine.netLink.LinkByName(hostVethName)
	if err != nil {
		return nil, errors.Wrapf(err,
			"bridge create veth pair: unable to look up host veth interface %s", hostVethName)
	}

	err = engine.netLink.LinkSetMaster(hostVethInterface, bridge)
	if err != nil {
		return nil, errors.Wrapf(err,
			"bridge create veth pair: unable to attach the veth interface %s to bridge", hostVethName)
	}

	return &current.Interface{
		Name: hostVethName,
		Mac:  hostVethInterface.Attrs().HardwareAddr.String(),
	}, nil
}

// RunIPAMPluginAdd invokes the IPAM plugin with the ADD command
func (engine *engine) RunIPAMPluginAdd(plugin string, netConf []byte) (*current.Result, error) {
	ipamResult, err := engine.ipam.ExecAdd(plugin, netConf)
	if err != nil {
		return nil, errors.Wrapf(err,
			"bridge ipam ADD: failed to execute plugin: %s", plugin)
	}

	result, err := current.NewResultFromResult(ipamResult)
	if err != nil {
		return nil, errors.Wrapf(err,
			"bridge IPAM ADD: unable to parse result '%s'", ipamResult.String())
	}

	// Accept 1 or 2 IP configurations (IPv4 only, IPv6 only, or dual-stack)
	if len(result.IPs) < 1 || len(result.IPs) > 2 {
		return nil, errors.Errorf(
			"bridge IPAM ADD: expected 1 or 2 IP configs, got %d", len(result.IPs))
	}

	// Validate each IP configuration
	for i, ip := range result.IPs {
		if ip.Address.Mask == nil || ip.Address.Mask.String() == zeroLengthIPString {
			return nil, errors.Errorf(
				"bridge IPAM ADD: IP address mask not set for IP[%d]", i)
		}
		if ip.Gateway == nil || ip.Gateway.String() == zeroLengthIPString {
			return nil, errors.Errorf(
				"bridge IPAM ADD: Gateway not set for IP[%d]", i)
		}
	}

	return result, nil
}

// ConfigureContainerVethInterface configures the container's veth interface,
// including setting up routes within the container
func (engine *engine) ConfigureContainerVethInterface(netnsName string, result *current.Result, interfaceName string) error {
	configureContext := newConfigureVethContext(
		interfaceName,
		result,
		engine.ip,
		engine.ipam,
		engine.netLink)

	return engine.ns.WithNetNSPath(netnsName, configureContext.run)
}

// ConfigureBridge configures the IP addresses of the bridge for all address families
func (engine *engine) ConfigureBridge(result *current.Result, bridge *netlink.Bridge) error {
	for _, ipConfig := range result.IPs {
		// Determine address family based on IP version
		family := syscall.AF_INET
		if ipConfig.Address.IP.To4() == nil {
			family = syscall.AF_INET6
		}

		addrs, err := engine.netLink.AddrList(bridge, family)
		if err != nil && err != syscall.ENOENT {
			return errors.Wrapf(err,
				"bridge configure: unable to list addresses for bridge %s",
				bridge.Attrs().Name)
		}

		resultBridgeNetwork := &net.IPNet{
			IP:   ipConfig.Gateway,
			Mask: ipConfig.Address.Mask,
		}
		resultBridgeCIDR := resultBridgeNetwork.String()

		addressExists := false
		hasConflictingGlobalAddr := false
		for _, addr := range addrs {
			if addr.IPNet.String() == resultBridgeCIDR {
				addressExists = true
				break
			}
			// For IPv6, ignore link-local addresses (fe80::/10) when checking for conflicts
			// The kernel automatically assigns link-local addresses to interfaces
			if family == syscall.AF_INET6 && addr.IP.IsLinkLocalUnicast() {
				continue
			}
			hasConflictingGlobalAddr = true
		}

		if addressExists {
			continue
		}

		if hasConflictingGlobalAddr {
			return errors.Errorf(
				"bridge configure: mismatch in bridge %s address for family %d",
				bridge.Attrs().Name, family)
		}

		bridgeAddr := &netlink.Addr{IPNet: resultBridgeNetwork}
		addrAddErr := engine.netLink.AddrAdd(bridge, bridgeAddr)
		if addrAddErr != nil && !strings.Contains(addrAddErr.Error(), fileExistsErrMsg) {
			return errors.Wrapf(addrAddErr,
				"bridge configure: unable to assign ip address to bridge %s",
				bridge.Attrs().Name)
		}
	}

	return nil
}

// GetInterfaceIPV4Address gets the ipv4 address of a given interface
// in the container
func (engine *engine) GetInterfaceIPV4Address(netnsName string, interfaceName string) (string, error) {
	ipv4Context := newGetContainerIPV4Context(interfaceName, engine.netLink)
	err := engine.ns.WithNetNSPath(netnsName, ipv4Context.run)
	if err != nil {
		return "", err
	}

	return ipv4Context.ipv4Addr, nil
}

// RunIPAMPluginDel invokes the IPAM plugin with the DEL command
func (engine *engine) RunIPAMPluginDel(plugin string, netconf []byte) error {
	err := engine.ipam.ExecDel(plugin, netconf)
	if err != nil {
		return errors.Wrapf(err,
			"bridge ipam DEL: failed to execute the plugin: %s", plugin)
	}

	return nil
}

// DeleteVeth deletes the veth interface in container
func (engine *engine) DeleteVeth(netnsName string, interfaceName string) error {
	delContext := newDeleteLinkContext(interfaceName, engine.ip)
	return engine.ns.WithNetNSPath(netnsName, delContext.run)
}
