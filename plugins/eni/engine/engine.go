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
	"strings"

	"github.com/aws/amazon-ecs-cni-plugins/pkg/cninswrapper"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/ec2metadata"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/ioutilwrapper"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/netlinkwrapper"
	log "github.com/cihub/seelog"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/pkg/errors"
)

const (
	metadataNetworkInterfacesPath                    = "network/interfaces/macs/"
	metadataNetworkInterfaceIDPathSuffix             = "interface-id"
	sysfsPathForNetworkDevices                       = "/sys/class/net/"
	sysfsPathForNetworkDeviceAddressSuffix           = "/address"
	metadataNetworkInterfaceIPV4SubnetCIDRPathSuffix = "/subnet-ipv4-cidr-block"
	metadataNetworkInterfaceIPV4AddressesSuffix      = "/local-ipv4s"
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
	var macAddresses []string
	macs, err := engine.metadata.GetMetadata(metadataNetworkInterfacesPath)
	if err != nil {
		return macAddresses, errors.Wrapf(err, "Error getting all mac addresses on the instance")
	}
	return strings.Split(macs, "\n"), nil
}

// GetMACAddressOfENI gets the mac address for a given ENI ID
func (engine *engine) GetMACAddressOfENI(macAddresses []string, eniID string) (string, error) {
	for _, macAddress := range macAddresses {
		interfaceID, err := engine.metadata.GetMetadata(metadataNetworkInterfacesPath + macAddress + metadataNetworkInterfaceIDPathSuffix)
		if err != nil {
			log.Warnf("Error getting interface id for mac address '%s': %v", macAddress, err)
			continue
		}
		if interfaceID == eniID {
			return strings.Split(macAddress, "/")[0], nil
		}
	}

	return "", fmt.Errorf("MAC address of interface '%s' not found", eniID)
}

// GetInterfaceDeviceName gets the device name on the host, given a mac address
func (engine *engine) GetInterfaceDeviceName(macAddress string) (string, error) {
	files, err := engine.ioutil.ReadDir(sysfsPathForNetworkDevices)
	if err != nil {
		return "", errors.Wrapf(err, "Error listing network devices from sys fs")
	}
	for _, file := range files {
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

	return "", fmt.Errorf("Network device name not found for '%s'", macAddress)
}

// GetIPV4GatewayNetmask gets the ipv4 gateway and the netmask from the instance
// metadata, given a mac address
func (engine *engine) GetIPV4GatewayNetmask(macAddress string) (string, string, error) {
	subnetCIDR, err := engine.metadata.GetMetadata(metadataNetworkInterfacesPath + macAddress + metadataNetworkInterfaceIPV4SubnetCIDRPathSuffix)
	if err != nil {
		return "", "", errors.Wrapf(err, "Error getting ipv4 subnet and cidr block for '%s'", macAddress)
	}
	parts := strings.Split(subnetCIDR, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("Unable to parse response from metadata service for ipv4 subnet and cidr: '%s' for '%s'", subnetCIDR, macAddress)
	}
	cidrBlock := parts[0]
	netmask := parts[1]

	if netmask == "" {
		return "", "", fmt.Errorf("Unable to parse response from metadata service for ipv4 subnet and cidr: '%s' for '%s'", subnetCIDR, macAddress)
	}

	parts = strings.Split(cidrBlock, ".")
	if len(parts) != 4 {
		return "", "", fmt.Errorf("Unable to parse the CIDR block from metadata service: '%s' for '%s'", cidrBlock, macAddress)
	}
	if parts[3] == "" {
		return "", "", fmt.Errorf("Unable to parse the CIDR block from metadata service: '%s' for '%s'", cidrBlock, macAddress)
	}

	return fmt.Sprintf("%s.%s.%s.1", parts[0], parts[1], parts[2]), netmask, nil
}

// DoesMACAddressMapToIPV4Address validates in the MAC Address for the ENI maps to the
// IPV4 Address specified
func (engine *engine) DoesMACAddressMapToIPV4Address(macAddress string, ipv4Address string) (bool, error) {
	addressesResponse, err := engine.metadata.GetMetadata(metadataNetworkInterfacesPath + macAddress + metadataNetworkInterfaceIPV4AddressesSuffix)
	if err != nil {
		return false, errors.Wrapf(err, "Error getting ipv4 addresses from metadata")
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
	eniLink, err := engine.netLink.LinkByName(deviceName)
	if err != nil {
		return errors.Wrapf(err, "Error getting link")
	}

	containerNS, err := engine.ns.GetNS(netns)
	if err != nil {
		return errors.Wrapf(err, "Error getting network namespace")
	}

	err = engine.netLink.LinkSetNsFd(eniLink, int(containerNS.Fd()))
	if err != nil {
		return errors.Wrapf(err, "Error moving ENI to container namespace")
	}

	toRun := &nsClosure{
		netLink:     engine.netLink,
		deviceName:  deviceName,
		ipv4Address: ipv4Address,
		netmask:     netmask,
	}
	err = engine.ns.WithNetNSPath(netns, toRun.run)
	if err != nil {
		return errors.Wrapf(err, "Error setting up ENI")
	}
	return nil
}

// nsClosure wraps the parameters and the method to configure the container's namespace
type nsClosure struct {
	netLink     netlinkwrapper.NetLink
	deviceName  string
	ipv4Address string
	netmask     string
}

// run defines the closure to execute within the container's namespace to configure it
// appropriately
func (closure *nsClosure) run(_ ns.NetNS) error {
	eniLink, err := closure.netLink.LinkByName(closure.deviceName)
	if err != nil {
		return errors.Wrapf(err, "Error getting link")
	}
	addr, err := closure.netLink.ParseAddr(fmt.Sprintf("%s/%s", closure.ipv4Address, closure.netmask))
	if err != nil {
		return errors.Wrapf(err, "Error parsing ipv4 address for the interface")
	}
	err = closure.netLink.AddrAdd(eniLink, addr)
	if err != nil {
		return errors.Wrapf(err, "Error adding ipv4 address to the interface")
	}
	err = closure.netLink.LinkSetUp(eniLink)
	if err != nil {
		return errors.Wrapf(err, "Error bringing up the ENI link")
	}

	return nil
}
