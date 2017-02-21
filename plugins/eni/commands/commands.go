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

	"github.com/aws/amazon-ecs-cni-plugins/pkg/cninswrapper"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/ec2metadata"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/ioutilwrapper"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/netlinkwrapper"
	"github.com/aws/amazon-ecs-cni-plugins/plugins/eni/engine"
	"github.com/aws/amazon-ecs-cni-plugins/plugins/eni/types"
	log "github.com/cihub/seelog"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/pkg/errors"
)

// Add invokes the command to add ENI to a container's namespace
func Add(args *skel.CmdArgs) error {
	return add(args, engine.NewEngine(
		ec2metadata.NewEC2Metadata(), ioutilwrapper.NewIOUtil(), netlinkwrapper.NewNetLink(), cninswrapper.NewNS()))
}

// Del invokes the command to remove ENI to a container's namespace
func Del(args *skel.CmdArgs) error {
	return nil
}

func add(args *skel.CmdArgs, engine engine.Engine) error {
	conf, err := types.NewConf(args)
	if err != nil {
		log.Errorf("Error loading config from args: %v", err)
		return err
	}

	allMACAddresses, err := engine.GetAllMACAddresses()
	if err != nil {
		log.Errorf("Error getting mac addresses: %v", err)
		return err
	}
	log.Debugf("Found mac addresses: %v", allMACAddresses)
	macAddressOfENI, err := engine.GetMACAddressOfENI(allMACAddresses, conf.ENIID)
	if err != nil {
		log.Errorf("Error finding the mac address for the ENI: %v", err)
		return err
	}
	log.Debugf("Found mac address for the ENI: %v", macAddressOfENI)
	networkDeviceName, err := engine.GetInterfaceDeviceName(macAddressOfENI)
	if err != nil {
		log.Errorf("Error finding network device for the ENI: %v", err)
		return err
	}
	log.Debugf("Found network device for the ENI: %v", networkDeviceName)
	ipv4Gateway, netmask, err := engine.GetIPV4GatewayNetmask(macAddressOfENI)
	if err != nil {
		log.Errorf("Error getting ipv4 gateway and netmask for ENI: %v", err)
		return err
	}
	log.Debugf("Found ipv4 gateway and netmask for ENI: %s %s", ipv4Gateway, netmask)
	ok, err := engine.DoesMACAddressMapToIPV4Address(macAddressOfENI, conf.IPV4Address)
	if err != nil {
		log.Errorf("Error validating ipv4 addresses for ENI: %v", err)
		return err
	}
	if !ok {
		errorMessage := "Unable to map ipv4 address of ENI to a mac address"
		log.Error(errorMessage)
		return fmt.Errorf(errorMessage)
	}

	log.Debugf("Found ipv4Addresses: %v", ok)
	err = engine.SetupContainerNamespace(args.Netns, networkDeviceName, conf.IPV4Address, netmask)
	if err != nil {
		return errors.Wrapf(err, "Error setting up container's network namespace")
	}
	return nil
}
