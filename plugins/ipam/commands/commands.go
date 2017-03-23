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
	"net"
	"time"

	"github.com/aws/amazon-ecs-cni-plugins/plugins/ipam/config"
	"github.com/aws/amazon-ecs-cni-plugins/plugins/ipam/ipstore"
	"github.com/cihub/seelog"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/pkg/errors"
)

// Add will return ip, gateway, routes which can be
// used in bridge plugin to configure veth pair and bridge
func Add(args *skel.CmdArgs) error {
	ipamConf, cniVersion, err := config.LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	dbConf, err := config.LoadDBConfig()
	if err != nil {
		return err
	}

	// Create the ip manager
	ipManager, err := ipstore.NewIPAllocator(dbConf, net.IPNet{
		IP:   ipamConf.IPV4Subnet.IP,
		Mask: ipamConf.IPV4Subnet.Mask})
	if err != nil {
		return err
	}
	defer ipManager.Close()

	err = verifyGateway(ipamConf.IPV4Gateway, ipManager)
	if err != nil {
		return err
	}

	nextIP, err := getIPV4Address(ipManager, ipamConf)
	if err != nil {
		return err
	}

	err = ipManager.Update(config.LastKnownIPKey, nextIP.IP.String())
	if err != nil {
		// This error will only impact how the next ip will be find, it shouldn't cause
		// the command to fail
		seelog.Errorf("add commands: update the last known ip failed: %v", err)
	}

	return types.PrintResult(constructResults(ipamConf, *nextIP), cniVersion)
}

// Del will release one ip address and update the last known ip
func Del(args *skel.CmdArgs) error {
	ipamConf, _, err := config.LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	dbConf, err := config.LoadDBConfig()
	if err != nil {
		return err
	}
	// Create the ip manager
	ipManager, err := ipstore.NewIPAllocator(dbConf, net.IPNet{
		IP:   ipamConf.IPV4Subnet.IP,
		Mask: ipamConf.IPV4Subnet.Mask,
	})
	if err != nil {
		return err
	}
	defer ipManager.Close()

	if ipamConf.IPV4Address.IP == nil {
		return errors.New("del commands: ip address is required for deletion")
	}

	ok, err := ipManager.Exists(ipamConf.IPV4Address.IP.String())
	if err != nil {
		return err
	}
	if !ok {
		return errors.Errorf("del commands: ip %v not existed in the db", ipamConf.IPV4Address)
	}

	err = ipManager.Release(ipamConf.IPV4Address.IP.String())
	if err != nil {
		return err
	}

	// Update the last known ip
	err = ipManager.Update("lastKnownIP", ipamConf.IPV4Address.IP.String())
	if err != nil {
		// This error will only impact how the next ip will be find, it shouldn't cause
		// the command to fail
		seelog.Errorf("del commands: update the last known ip failed: %v", err)
	}

	return nil
}

// getIPV4Address return the available ip address from configuration if specified or from the
// db if not explicitly specified in the configuration
func getIPV4Address(ipManager ipstore.IPAllocator, conf *config.IPAMConfig) (*net.IPNet, error) {
	assignedAddress := &net.IPNet{
		IP:   conf.IPV4Address.IP,
		Mask: conf.IPV4Address.Mask,
	}
	if assignedAddress.IP != nil {
		// IP was specifed in the configuration, try to assign this ip as used
		// if this ip has already been used, it will return an error
		err := ipManager.Assign(assignedAddress.IP.String(), time.Now().UTC().String())
		if err != nil {
			return nil, errors.Wrapf(err, "getIPV4Address commands: failed to mark this ip %v as used", assignedAddress)
		}
	} else {
		// Get the next ip from db based on the last used ip
		startIP := conf.IPV4Subnet.IP.Mask(conf.IPV4Subnet.Mask)
		ok, err := ipManager.Exists(config.LastKnownIPKey)
		if err != nil {
			return nil, errors.Wrap(err, "getIPV4Address commands: failed to read the db")
		}
		if ok {
			lastKnownIPStr, err := ipManager.Get(config.LastKnownIPKey)
			if err != nil {
				return nil, errors.Wrap(err, "getIPV4Address commands: failed to get lask known ip from the db")
			}
			startIP = net.ParseIP(lastKnownIPStr)
		}

		ipManager.SetLastKnownIP(startIP)
		nextIP, err := ipManager.GetAvailableIP(time.Now().UTC().String())
		if err != nil {
			return nil, errors.Wrap(err, "getIPV4Address commands: failed to get available ip from the db")
		}
		assignedAddress.IP = net.ParseIP(nextIP)
		assignedAddress.Mask = conf.IPV4Subnet.Mask
	}
	return assignedAddress, nil
}

// constructResults construct the struct from IPAM configuration to be used
// by bridge plugin
func constructResults(conf *config.IPAMConfig, ipv4 net.IPNet) *current.Result {
	result := &current.Result{}
	ipversion := "4"

	// Currently only ipv4 is supported
	if ipv4.IP.To4() == nil {
		return nil
	}

	ipConfig := &current.IPConfig{
		Version: ipversion,
		Address: ipv4,
		Gateway: conf.IPV4Gateway,
	}

	result.IPs = []*current.IPConfig{ipConfig}
	result.Routes = conf.IPV4Routes

	return result
}

// verifyGateway checks if this gateway address is the default gateway or used by other container
func verifyGateway(gw net.IP, ipManager ipstore.IPAllocator) error {
	ok, err := ipManager.Exists(gw.String())
	if err != nil {
		return errors.Wrap(err, "verifyGateway commands: failed to read the db")
	}

	if ok {
		// Gateway address has already been used, check if it's used by default gateway
		value, err := ipManager.Get(gw.String())
		if err != nil {
			return errors.Wrap(err, "verifyGateway commands: failed to get the value of gateway")
		}
		if value == config.GatewayValue {
			return nil
		} else {
			return errors.New("verifyGateway commands: ip of gateway has already been used")
		}
	} else {
		err := ipManager.Assign(gw.String(), config.GatewayValue)
		if err != nil {
			return errors.Wrap(err, "verifyGateway commands: failed to update gateway into the db")
		}
	}

	return nil
}
