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
	"strings"

	"github.com/aws/amazon-ecs-cni-plugins/pkg/cninswrapper"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/ec2metadata"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/ioutilwrapper"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/netlinkwrapper"
	log "github.com/cihub/seelog"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

const (
	metadataNetworkInterfacesPath               = "network/interfaces/macs/"
	metadataNetworkInterfaceIDPathSuffix        = "interface-id"
	sysfsPathForNetworkDevices                  = "/sys/class/net/"
	sysfsPathForNetworkDeviceAddressSuffix      = "/address"
	metadataNetworkInterfaceIPV4CIDRPathSuffix  = "/subnet-ipv4-cidr-block"
	metadataNetworkInterfaceIPV4AddressesSuffix = "/local-ipv4s"
)

// Engine represents the execution engine for the ENI plugin. It defines all the
// operations performed by the plugin
type Engine interface {
	GetAllMACAddresses() ([]string, error)
	GetMACAddressOfENI(macAddresses []string, eniID string) (string, error)
	GetInterfaceDeviceName(macAddress string) (string, error)
	GetIPV4GatewayNetmask(macAddress string) (string, string, error)
	DoesMACAddressMapToIPV4Address(macAddress string, ipv4Address string) (bool, error)
	SetupContainerNamespace(netns string, deviceName string, ipv4Address string, netmask string) error
}

type engine struct {
	metadata ec2metadata.EC2Metadata
	ioutil   ioutilwrapper.IOUtil
	netLink  netlinkwrapper.NetLink
	ns       cninswrapper.NS
}

// NewEngine creates a new Engine object
func NewEngine(metadata ec2metadata.EC2Metadata, ioutil ioutilwrapper.IOUtil, netLink netlinkwrapper.NetLink, ns cninswrapper.NS) Engine {
	return &engine{
		metadata: metadata,
		ioutil:   ioutil,
		netLink:  netLink,
		ns:       ns,
	}
}

// GetAllMACAddresses gets a list of mac addresses for all interfaces from the instance
// metadata service
func (engine *engine) GetAllMACAddresses() ([]string, error) {
	macs, err := engine.metadata.GetMetadata(metadataNetworkInterfacesPath)
	if err != nil {
		return nil, errors.Wrap(err, "Error getting all mac addresses on the instance from instance metadata")
	}
	return strings.Split(macs, "\n"), nil
}

// GetMACAddressOfENI gets the mac address for a given ENI ID
func (engine *engine) GetMACAddressOfENI(macAddresses []string, eniID string) (string, error) {
	for _, macAddress := range macAddresses {
		// TODO Use fmt.Sprintf and wrap that in a method
		interfaceID, err := engine.metadata.GetMetadata(metadataNetworkInterfacesPath + macAddress + metadataNetworkInterfaceIDPathSuffix)
		if err != nil {
			log.Warnf("Error getting interface id for mac address '%s': %v", macAddress, err)
			continue
		}
		if interfaceID == eniID {
			// MAC addresses retrieved from the metadata service end with the '/' character. Strip it off.
			return strings.Split(macAddress, "/")[0], nil
		}
	}

	return "", errors.Errorf("MAC address of interface '%s' not found", eniID)
}

// GetInterfaceDeviceName gets the device name on the host, given a mac address
func (engine *engine) GetInterfaceDeviceName(macAddress string) (string, error) {
	files, err := engine.ioutil.ReadDir(sysfsPathForNetworkDevices)
	if err != nil {
		return "", errors.Wrap(err, "Error listing network devices from sys fs")
	}
	for _, file := range files {
		// Read the 'address' file in sys for the device. An example here is: if reading for device
		// 'eth1', read the '/sys/class/net/eth1/address' file to get the address of the device
		// TODO Use fmt.Sprintf and wrap that in a method
		addressFile := sysfsPathForNetworkDevices + file.Name() + sysfsPathForNetworkDeviceAddressSuffix
		contents, err := engine.ioutil.ReadFile(addressFile)
		if err != nil {
			log.Warnf("Error reading contents of the address file for device '%s': %v", file.Name(), err)
			continue
		}
		if strings.Contains(string(contents), macAddress) {
			return file.Name(), nil
		}
	}

	return "", errors.Errorf("Network device name not found for '%s'", macAddress)
}

// GetIPV4GatewayNetmask gets the ipv4 gateway and the netmask from the instance
// metadata, given a mac address
func (engine *engine) GetIPV4GatewayNetmask(macAddress string) (string, string, error) {
	// TODO Use fmt.Sprintf and wrap that in a method
	cidrBlock, err := engine.metadata.GetMetadata(metadataNetworkInterfacesPath + macAddress + metadataNetworkInterfaceIPV4CIDRPathSuffix)
	if err != nil {
		return "", "", errors.Wrapf(err, "Error getting ipv4 subnet and cidr block for '%s'", macAddress)
	}

	return getIPV4GatewayNetmask(cidrBlock)
}

func getIPV4GatewayNetmask(cidrBlock string) (string, string, error) {
	// The IPV4 CIDR block is of the format ip-addr/netmask
	ip, ipNet, err := net.ParseCIDR(cidrBlock)
	if err != nil {
		return "", "", errors.Wrapf(err, "Unable to parse response from instance metadata for ipv4 cidr: '%s'", cidrBlock)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return "", "", errors.Errorf("Unable to parse ipv4 gateway from cidr block '%s'", cidrBlock)
	}

	ip4[3] = ip4[3] + 1
	maskOnes, _ := ipNet.Mask.Size()
	return ip4.String(), fmt.Sprintf("%d", maskOnes), nil
}

// DoesMACAddressMapToIPV4Address validates in the MAC Address for the ENI maps to the
// IPV4 Address specified
func (engine *engine) DoesMACAddressMapToIPV4Address(macAddress string, ipv4Address string) (bool, error) {
	// TODO Use fmt.Sprintf and wrap that in a method
	addressesResponse, err := engine.metadata.GetMetadata(metadataNetworkInterfacesPath + macAddress + metadataNetworkInterfaceIPV4AddressesSuffix)
	if err != nil {
		return false, errors.Wrap(err, "Error getting ipv4 addresses from instance metadata")
	}
	for _, address := range strings.Split(addressesResponse, "\n") {
		if address == ipv4Address {
			return true, nil
		}
	}
	return false, nil
}

// SetupContainerNamespace configures the network namespace of the container with
// the ipv4 address and routes to use the ENI interface
func (engine *engine) SetupContainerNamespace(netns string, deviceName string, ipv4Address string, netmask string) error {
	// Get the device link for the ENI
	eniLink, err := engine.netLink.LinkByName(deviceName)
	if err != nil {
		return errors.Wrapf(err, "Error getting link for device '%s'", deviceName)
	}

	// Get the handle for the container's network namespace
	containerNS, err := engine.ns.GetNS(netns)
	if err != nil {
		return errors.Wrapf(err, "Error getting network namespace for '%s'", netns)
	}

	// Assign the ENI device to container's network namespace
	err = engine.netLink.LinkSetNsFd(eniLink, int(containerNS.Fd()))
	if err != nil {
		return errors.Wrapf(err, "Error moving device '%s' to container namespace '%s'", deviceName, netns)
	}

	// Generate the closure to execute within the container's namespace
	toRun, err := newNSClosure(engine.netLink, deviceName, ipv4Address, netmask)
	if err != nil {
		return errors.Wrap(err, "Error creating closure to execute in container namespace")
	}

	// Execute the closure within the container's namespace
	err = engine.ns.WithNetNSPath(netns, toRun.run)
	if err != nil {
		return errors.Wrapf(err, "Error setting up device '%s' in namespace '%s'", deviceName, netns)
	}
	return nil
}

// nsClosure wraps the parameters and the method to configure the container's namespace
type nsClosure struct {
	netLink    netlinkwrapper.NetLink
	deviceName string
	ipv4Addr   *netlink.Addr
}

// newNSClosure creates a new nsClosure object
func newNSClosure(netLink netlinkwrapper.NetLink, deviceName string, ipv4Address string, netmask string) (*nsClosure, error) {
	addr, err := netLink.ParseAddr(fmt.Sprintf("%s/%s", ipv4Address, netmask))
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing ipv4 address for the interface")
	}

	return &nsClosure{
		netLink:    netLink,
		deviceName: deviceName,
		ipv4Addr:   addr,
	}, nil
}

// run defines the closure to execute within the container's namespace to configure it
// appropriately
func (closure *nsClosure) run(_ ns.NetNS) error {
	// Get the link for the ENI device
	eniLink, err := closure.netLink.LinkByName(closure.deviceName)
	if err != nil {
		return errors.Wrapf(err, "Error getting link for device '%s'", closure.deviceName)
	}

	// Add the IPV4 Address to the link
	err = closure.netLink.AddrAdd(eniLink, closure.ipv4Addr)
	if err != nil {
		return errors.Wrap(err, "Error adding ipv4 address to the interface")
	}

	// Bring it up
	err = closure.netLink.LinkSetUp(eniLink)
	if err != nil {
		return errors.Wrap(err, "Error bringing up the device")
	}

	return nil
}
