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

package main

import (
	"net"
	"time"

	"github.com/aws/amazon-ecs-cni-plugins/plugins/ipam/config"
	"github.com/aws/amazon-ecs-cni-plugins/plugins/ipam/ipstore"
	"github.com/aws/amazon-ecs-cni-plugins/plugins/ipam/version/cnispec"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/pkg/errors"
)

func main() {
	skel.PluginMain(cmdAdd, cmdDel, cnispec.GetSpecVersionSupported())
}

// cmdAdd will return ip, gateway, routes which can be
// used in bridge plugin to configure veth pair and bridge
func cmdAdd(args *skel.CmdArgs) error {
	conf, cniVersion, err := config.LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	// Create the ip manager
	timeout := config.DefaultConnectionTimeout
	if conf.Timeout != "" {
		duration, err := time.ParseDuration(conf.Timeout)
		if err != nil {
			return errors.Errorf("parsing duration from string failed: %v", err)
		}
		timeout = duration
	}

	dbConf := &ipstore.Config{
		PersistConnection: false,
		Bucket:            conf.Bucket,
		ConnectionTimeout: timeout,
		DB:                conf.DB,
	}
	ipManager, err := ipstore.New(dbConf, net.IPNet{
		IP:   conf.Subnet.IP,
		Mask: conf.Subnet.Mask,
	})
	if err != nil {
		return err
	}
	defer ipManager.Close()

	// Assign an available IP from the db
	assignedIP := net.IPNet{
		IP:   conf.IPAddress.IP,
		Mask: conf.IPAddress.Mask,
	}
	start := conf.Subnet.IP.Mask(conf.Subnet.Mask)
	if assignedIP.IP == nil {
		// First get the previous referenced ip address from boltdb
		exist, err := ipManager.Exists(config.LastKnownIPKey)
		if err != nil {
			return err
		}

		if exist {
			lastKnownIPStr, err := ipManager.Get(config.LastKnownIPKey)
			if err != nil {
				return err
			}
			start = net.ParseIP(lastKnownIPStr)
		}

		ipManager.SetLastKnownIP(start)
		// Get the next available ip from boltdb
		nextIP, err := ipManager.GetAvailableIP(time.Now().UTC().String())
		// Get the ip from boltdb failed
		if err != nil {
			return err
		}

		assignedIP.IP = net.ParseIP(nextIP)
		assignedIP.Mask = conf.Subnet.Mask
	} else {
		// check whether this ip is available
		exist, err := ipManager.Exists(assignedIP.IP.String())
		if err != nil {
			return err
		}
		if exist {
			return errors.Errorf("ip %v has already been used", assignedIP)
		}

		err = ipManager.Assign(assignedIP.IP.String(), time.Now().UTC().String())
		if err != nil {
			return err
		}
	}

	// update the last known ip
	err = ipManager.Update(config.LastKnownIPKey, assignedIP.IP.String())
	if err != nil {
		return err
	}

	// Mark the gateway as used
	exist, err := ipManager.Exists(conf.Gateway.String())
	if err != nil {
		return err
	}
	if !exist {
		err := ipManager.Assign(conf.Gateway.String(), time.Now().UTC().String())
		if err != nil {
			return err
		}
	}

	result := &current.Result{}

	var ipversion string
	if assignedIP.IP.To4() != nil {
		ipversion = "4"
	} else if assignedIP.IP.To16() != nil {
		ipversion = "6"
	} else {
		return errors.New("invalid ip address")
	}
	ipConfig := &current.IPConfig{
		Version: ipversion,
		Address: assignedIP,
		Gateway: conf.Gateway,
	}

	result.IPs = []*current.IPConfig{ipConfig}
	result.Routes = conf.Routes

	return types.PrintResult(result, cniVersion)
}

// cmdDel will release one ip address and update the last known ip
func cmdDel(args *skel.CmdArgs) error {
	conf, _, err := config.LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	// convert from types.IPNet to net.IPNet
	subnet := net.IPNet{
		IP:   conf.Subnet.IP,
		Mask: conf.Subnet.Mask,
	}

	ipAddress := net.IPNet{
		IP:   conf.IPAddress.IP,
		Mask: conf.IPAddress.Mask,
	}

	timeout := config.DefaultConnectionTimeout
	if conf.Timeout != "" {
		duration, err := time.ParseDuration(conf.Timeout)
		if err != nil {
			return errors.Errorf("parsing duration from string failed: %v", err)
		}
		timeout = duration
	}
	// Open the db
	dbConf := &ipstore.Config{
		PersistConnection: false,
		Bucket:            conf.Bucket,
		ConnectionTimeout: timeout,
		DB:                conf.DB,
	}
	ipManager, err := ipstore.New(dbConf, subnet)
	if err != nil {
		return err
	}
	defer ipManager.Close()

	exist, err := ipManager.Exists(ipAddress.IP.String())
	if err != nil {
		return err
	}
	if !exist {
		return errors.Errorf("ip %v not existed in the db", conf.IPAddress)
	}

	err = ipManager.Release(ipAddress.IP.String())
	if err != nil {
		return err
	}

	// Update the last known ip
	return ipManager.Update("lastKnownIP", ipAddress.IP.String())
}
