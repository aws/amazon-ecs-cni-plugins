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

package utils

import (
	"net"
	"time"

	"github.com/aws/amazon-ecs-cni-plugins/plugins/ipam/config"
	"github.com/aws/amazon-ecs-cni-plugins/plugins/ipam/ipstore"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/pkg/errors"
)

// GetIPV4Address return the ip address from configuration
func GetIPV4Address(ipManager ipstore.IPAllocator, conf *config.IPAMConfig) (*net.IPNet, error) {
	assignedIP := &net.IPNet{
		IP:   conf.IPV4Address.IP,
		Mask: conf.IPV4Address.Mask,
	}
	if assignedIP.IP != nil {
		// IP was specifed in the configuration
		ok, err := ipManager.Exists(assignedIP.IP.String())
		if err != nil {
			return nil, errors.Wrap(err, "getIPV4Address main: failed to read the db")
		}
		if ok {
			return nil, errors.Errorf("getIPV4Address main: ip %v has already been used", assignedIP)
		}

		// Record this ip as used
		err = ipManager.Assign(assignedIP.IP.String(), time.Now().UTC().String())
		if err != nil {
			return nil, errors.Wrapf(err, "getIPV4Address main: failed to mark this ip %v as used", assignedIP)
		}
	} else {
		// Get the next ip from db based on the last used ip
		startIP := conf.IPV4Subnet.IP.Mask(conf.IPV4Subnet.Mask)
		ok, err := ipManager.Exists(config.LastKnownIPKey)
		if err != nil {
			return nil, errors.Wrap(err, "getIPV4Address main: failed to read the db")
		}
		if ok {
			lastKnownIPStr, err := ipManager.Get(config.LastKnownIPKey)
			if err != nil {
				return nil, errors.Wrap(err, "getIPV4Address main: failed to get lask known ip from the db")
			}
			startIP = net.ParseIP(lastKnownIPStr)
		}

		ipManager.SetLastKnownIP(startIP)
		nextIP, err := ipManager.GetAvailableIP(time.Now().UTC().String())
		if err != nil {
			return nil, errors.Wrap(err, "getIPV4Address main: failed to get available ip from the db")
		}
		assignedIP.IP = net.ParseIP(nextIP)
		assignedIP.Mask = conf.IPV4Subnet.Mask
	}
	return assignedIP, nil
}

// ConstructResults construct the struct from IPAM configuration to be used
// by bridge plugin
func ConstructResults(conf *config.IPAMConfig, ipv4 net.IPNet) *current.Result {
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
	result.Routes = conf.Routes

	return result
}

// VerifyGateway checks if this gateway address is the default gateway or used by other container
func VerifyGateway(gw net.IP, ipManager ipstore.IPAllocator) error {
	ok, err := ipManager.Exists(gw.String())
	if err != nil {
		return errors.Wrap(err, "verifyGateway main: failed to read the db")
	}

	if ok {
		// Gateway has already been used, check if it's used by default gateway
		value, err := ipManager.Get(gw.String())
		if err != nil {
			return errors.Wrap(err, "verifyGateway main: failed to get the value of gateway")
		}
		if value == config.GatewayValue {
			return nil
		} else {
			return errors.New("verifyGateway main: ip of gateway has already been used")
		}
	} else {
		err := ipManager.Assign(gw.String(), config.GatewayValue)
		if err != nil {
			return errors.Wrap(err, "verifyGateway main: failed to update gateway into the db")
		}
	}

	return nil
}
