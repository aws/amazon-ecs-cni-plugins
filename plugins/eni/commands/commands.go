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

package commands

import (
	"fmt"

	"github.com/aws/amazon-ecs-cni-plugins/plugins/eni/engine"
	"github.com/aws/amazon-ecs-cni-plugins/plugins/eni/types"
	log "github.com/cihub/seelog"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/pkg/errors"
)

var (
	unmappedIPV4AddressError = errors.New(
		"add commands: unable to map ipv4 address of ENI to a mac address")
	unmappedIPV6AddressError = errors.New(
		"add commands: unable to map ipv6 address of ENI to a mac address")
	dhclientNotFoundError = errors.New(
		"add commands: unable to find the dhclient executable in PATH")
)

// Add invokes the command to add ENI to a container's namespace
func Add(args *skel.CmdArgs) error {
	return add(args, engine.New())
}

// Del invokes the command to remove ENI from a container's namespace
func Del(args *skel.CmdArgs) error {
	return del(args, engine.New())
}

func add(args *skel.CmdArgs, engine engine.Engine) error {
	conf, err := types.NewConf(args)
	if err != nil {
		// TODO: We log and return errors throughout this function.
		// Either should be sufficient.
		log.Errorf("Error loading config from args: %v", err)
		return err
	}

	if ok := engine.IsDHClientInPath(); !ok {
		log.Errorf("Unable to find the dhclient executable")
		return dhclientNotFoundError
	}

	macAddressOfENI, err := getMACAddressOfENI(conf, engine)
	if err != nil {
		return err
	}

	// Get the interface name of the device by scanning sysfs
	networkDeviceName, err := engine.GetInterfaceDeviceName(macAddressOfENI)
	if err != nil {
		log.Errorf("Unable to find network device for the ENI: %v", err)
		return err
	}
	log.Debugf("Found network device for the ENI: %v", networkDeviceName)

	// Get the ipv4 gateway and subnet mask for the ENI. This will be
	// required for adding routes in the container's namespace
	ipv4Gateway, ipv4Netmask, err := engine.GetIPV4GatewayNetmask(macAddressOfENI)
	if err != nil {
		log.Errorf("Unable to get ipv4 gateway and netmask for ENI: %v", err)
		return err
	}
	log.Debugf("Found ipv4 gateway and netmask for ENI: %s %s", ipv4Gateway, ipv4Netmask)

	ipv6Address := ""
	if conf.IPV6Address != "" {
		// Config contains an ipv6 address, figure out the subnet mask
		ipv6Netmask, err := engine.GetIPV6Netmask(macAddressOfENI)
		if err != nil {
			log.Errorf("Unable to get ipv6 netmask for ENI: %v", err)
			return err
		}
		ipv6Address = fmt.Sprintf("%s/%s", conf.IPV6Address, ipv6Netmask)
	}

	// Everything's setup. We have all the parameters needed to configure
	// the network namespace of the ENI. Invoke SetupContainerNamespace to
	// do the same
	err = engine.SetupContainerNamespace(args.Netns, networkDeviceName,
		fmt.Sprintf("%s/%s", conf.IPV4Address, ipv4Netmask), ipv6Address)
	if err != nil {
		log.Errorf("Unable to setup container's namespace: %v", err)
		return err
	}
	log.Debug("ENI has been assigned to the container's namespace")

	return nil
}

func getMACAddressOfENI(conf *types.NetConf, engine engine.Engine) (string, error) {
	// TODO: If we can get this information from the config, we can optimize
	// the workflow by getting rid of this, or by making this optional (only
	// in cases where mac address hasn't been specified)
	allMACAddresses, err := engine.GetAllMACAddresses()
	if err != nil {
		log.Errorf("Unable to get the list of mac addresses on the host: %v", err)
		return "", err
	}
	log.Debugf("Found mac addresses: %v", allMACAddresses)

	// Get the mac address of the ENI based on the ENIID by matching it
	// against the list of all mac addresses obtained in the previous step.
	macAddressOfENI, err := engine.GetMACAddressOfENI(allMACAddresses, conf.ENIID)
	if err != nil {
		log.Errorf("Unable to find the mac address for the ENI: %v", err)
		return "", err
	}
	log.Debugf("Found mac address for the ENI: %v", macAddressOfENI)

	// Validation to ensure that we've been given the correct parameters.
	// Check if the ipv4 address of the ENI maps to the mac address of the
	// ENI.
	err = doesMACAddressMapToIPV4Address(engine, macAddressOfENI, conf.IPV4Address)
	if err != nil {
		return "", err
	}
	log.Debugf("Found ipv4Address for the ENI: %v", macAddressOfENI)

	// Check if the ipv6 address of the ENI maps to the mac address of the
	// ENI.
	if conf.IPV6Address != "" {
		err = doesMACAddressMapToIPV6Address(engine, macAddressOfENI, conf.IPV6Address)
		if err != nil {
			return "", err
		}
	}
	log.Debugf("Found ipv6Address for the ENI: %v", macAddressOfENI)

	return macAddressOfENI, nil
}

func doesMACAddressMapToIPV4Address(engine engine.Engine, macAddressOfENI string, ipv4Address string) error {
	ok, err := engine.DoesMACAddressMapToIPV4Address(macAddressOfENI, ipv4Address)
	if err != nil {
		log.Errorf("Error validating ipv4 addresses for ENI: %v", err)
		return err
	}
	if !ok {
		log.Error("Unable to validate ipv4 address for ENI: %v", unmappedIPV4AddressError)
		return unmappedIPV4AddressError
	}

	return nil
}

func doesMACAddressMapToIPV6Address(engine engine.Engine, macAddressOfENI string, ipv6Address string) error {
	ok, err := engine.DoesMACAddressMapToIPV6Address(macAddressOfENI, ipv6Address)
	if err != nil {
		log.Errorf("Error validating ipv6 addresses for ENI: %v", err)
		return err
	}
	if !ok {
		log.Error("Unable to validate ipv6 address for ENI: %v", unmappedIPV6AddressError)
		return unmappedIPV6AddressError
	}

	return nil
}

// del removes the ENI setup within the container's namespace. It stops the dhclient
// process so that the ENI device can be brought down properly
func del(args *skel.CmdArgs, engine engine.Engine) error {
	conf, err := types.NewConf(args)
	if err != nil {
		// TODO: We log and return errors throughout this function.
		// Either should be sufficient.
		log.Errorf("Error loading config from args: %v", err)
		return err
	}

	stopDHClient6 := false
	if conf.IPV6Address != "" {
		stopDHClient6 = true
	}
	// Valid config. Tear it down!
	err = engine.TeardownContainerNamespace(args.Netns, conf.MACAddress, stopDHClient6)
	if err != nil {
		log.Errorf("Unable to teardown container's namespace: %v", err)
		return err
	}

	return nil
}
