// Copyright 2017-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
	"net"
	"time"

	"github.com/aws/amazon-ecs-cni-plugins/pkg/utils"
	"github.com/aws/amazon-ecs-cni-plugins/plugins/eni/engine"
	"github.com/aws/amazon-ecs-cni-plugins/plugins/eni/types"

	log "github.com/cihub/seelog"
	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/pkg/errors"
)

const (
	ec2InstanceMetadataBackoffMin      = 100 * time.Millisecond
	ec2InstanceMetadataBackoffMax      = 1 * time.Second
	ec2InstanceMetadataBackoffMultiple = 2
	ec2InstanceMetadataBackoffJitter   = 0.2
	ec2InstanceMetadataTimeout         = 1 * time.Minute
)

var (
	unmappedIPV4AddressError = errors.New(
		"add commands: unable to map ipv4 address of ENI to a mac address")
	unmappedIPV6AddressError = errors.New(
		"add commands: unable to map ipv6 address of ENI to a mac address")
)

// Add invokes the command to add ENI to a container's namespace
func Add(args *skel.CmdArgs) error {
	defer log.Flush()
	return add(args, engine.New())
}

// Del invokes the command to remove ENI from a container's namespace
func Del(args *skel.CmdArgs) error {
	defer log.Flush()
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

	macAddressOfENI := conf.MACAddress
	// Get the interface name of the device by scanning links
	networkDeviceName, err := engine.GetInterfaceDeviceName(macAddressOfENI)
	if err != nil {
		log.Errorf("Unable to find network device for ENI (mac address=%s): %v", macAddressOfENI, err)
		return err
	}
	log.Infof("Found network device for the ENI (mac address=%s): %s", macAddressOfENI, networkDeviceName)

	ipv4Gateway := ""
	ipv4Netmask := ""
	var ipv4Net *net.IPNet

	if conf.SubnetGatewayIPV4Address == "" {
		// Get the ipv4 gateway and subnet mask for the ENI. This will be
		// required for adding routes in the container's namespace
		ipv4Gateway, ipv4Netmask, err = engine.GetIPV4GatewayNetmask(conf.MACAddress)

		if err != nil {
			log.Errorf("Unable to get ipv4 gateway and netmask for ENI (device name=%s): %v",
				networkDeviceName, err)
			return err
		}
		log.Infof("Found ipv4 gateway and netmask for ENI (device name=%s): %s %s",
			networkDeviceName, ipv4Gateway, ipv4Netmask)
	} else {
		ipv4Gateway, ipv4Netmask, err = utils.ParseIPV4GatewayNetmask(conf.SubnetGatewayIPV4Address)
		if err != nil {
			log.Errorf("Unable to parse ipv4 gateway and netmask for ENI (device name=%s): %v",
				networkDeviceName, err)
			return err
		}
		log.Infof("Read ipv4 gateway and netmask from config for ENI (device name=%s): %s %s",
			networkDeviceName, ipv4Gateway, ipv4Netmask)
	}
	ipv4Address := fmt.Sprintf("%s/%s", ipv4Gateway, ipv4Netmask)
	_, ipv4Net, err = net.ParseCIDR(ipv4Address)
	if err != nil {
		return errors.Wrapf(err, "add eni: failed to parse ipv4 gateway netmask: %s", ipv4Address)
	}
	ips := []*current.IPConfig{
		{
			Version: "4",
			Address: *ipv4Net,
		},
	}

	ipv6Address := ""
	ipv6Gateway := ""
	if conf.IPV6Address != "" {
		// Config contains an ipv6 address, figure out the subnet mask
		ipv6Netmask, err := engine.GetIPV6PrefixLength(macAddressOfENI)
		if err != nil {
			log.Errorf("Unable to get ipv6 netmask for ENI (device name=%s): %v", networkDeviceName, err)
			return err
		}
		ipv6Address = fmt.Sprintf("%s/%s", conf.IPV6Address, ipv6Netmask)
		log.Debugf("IPV6 address (device name=%s): %v", networkDeviceName, ipv6Address)

		// Next, figure out the gateway ip
		ipv6Gateway, err = engine.GetIPV6Gateway(networkDeviceName)
		if err != nil {
			log.Errorf("Unable to get ipv6 gateway for ENI (device name=%s): %v", networkDeviceName, err)
			return err
		}
		log.Infof("IPV6 Gateway IP (device name=%s): %v", networkDeviceName, ipv6Gateway)
		_, ipv6net, err := net.ParseCIDR(ipv6Address)
		if err != nil {
			return errors.Wrapf(err, "add eni: failed to parse ipv6 gateway: %s", ipv6Address)
		}

		ips = append(ips, &current.IPConfig{
			Version: "6",
			Address: *ipv6net,
		})
	}

	// Everything's prepped. We have all the parameters needed to configure
	// the network namespace of the ENI. Invoke SetupContainerNamespace to
	// do the same
	err = engine.SetupContainerNamespace(args, networkDeviceName, macAddressOfENI,
		fmt.Sprintf("%s/%s", conf.IPV4Address, ipv4Netmask),
		ipv6Address, ipv4Gateway, ipv6Gateway, conf.BlockIMDS)
	if err != nil {
		log.Errorf("Unable to setup container's namespace (device name=%s): %v", networkDeviceName, err)
		return err
	}
	log.Infof("ENI %s (device name=%s) has been assigned to the container's namespace", conf.MACAddress, networkDeviceName)

	result := &current.Result{
		Interfaces: []*current.Interface{
			{
				Name: networkDeviceName,
				Mac:  macAddressOfENI,
			},
		},
		IPs: ips,
	}

	return cnitypes.PrintResult(result, conf.CNIVersion)
}

// del removes the ENI setup within the container's namespace.
func del(args *skel.CmdArgs, engine engine.Engine) error {
	return nil
}
