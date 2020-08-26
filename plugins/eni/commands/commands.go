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
	"net"
	"time"

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

	ips := []*current.IPConfig{}

	for _, addr := range conf.IPAddresses {
		ipAddr, ipNet, err := net.ParseCIDR(addr)
		if err != nil {
			log.Errorf("Unable to parse IP address %s for ENI (mac address=%s): %v", addr, macAddressOfENI, err)
			return err
		}

		ipNet.IP = ipAddr

		ipv := "4"
		if ipAddr.To4() == nil {
			ipv = "6"
		}

		ips = append(ips, &current.IPConfig{
			Version: ipv,
			Address: *ipNet,
		})
	}

	// Everything's prepped. We have all the parameters needed to configure
	// the network namespace of the ENI. Invoke SetupContainerNamespace to
	// do the same
	err = engine.SetupContainerNamespace(
		args, networkDeviceName, macAddressOfENI,
		conf.IPAddresses, conf.GatewayIPAddresses,
		conf.BlockIMDS, conf.StayDown, conf.MTU)
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
