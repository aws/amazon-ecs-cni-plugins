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
	defer seelog.Flush()
	ipamConf, cniVersion, err := config.LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	dbConf, err := config.LoadDBConfig()
	if err != nil {
		return err
	}

	// Create the ip manager with dual-stack support
	var subnetV4, subnetV6 *net.IPNet
	if ipamConf.HasIPv4() {
		subnetV4 = &net.IPNet{
			IP:   ipamConf.IPV4Subnet.IP,
			Mask: ipamConf.IPV4Subnet.Mask,
		}
	}
	if ipamConf.HasIPv6() {
		subnetV6 = &net.IPNet{
			IP:   ipamConf.IPV6Subnet.IP,
			Mask: ipamConf.IPV6Subnet.Mask,
		}
	}

	ipManager, err := ipstore.NewIPAllocatorDualStack(dbConf, subnetV4, subnetV6)
	if err != nil {
		return err
	}
	defer ipManager.Close()

	return add(ipManager, ipamConf, cniVersion)
}

func add(ipManager ipstore.IPAllocator, ipamConf *config.IPAMConfig, cniVersion string) error {
	var ipv4Result, ipv6Result *net.IPNet

	// Handle IPv4 if configured
	if ipamConf.HasIPv4() {
		err := verifyGateway(ipamConf.IPV4Gateway, ipManager)
		if err != nil {
			return err
		}

		ipv4, err := getIPV4Address(ipManager, ipamConf)
		if err != nil {
			return err
		}
		ipv4Result = ipv4

		err = ipManager.Update(config.LastKnownIPKey, ipv4.IP.String())
		if err != nil {
			// This error will only impact how the next ip will be found, it shouldn't cause
			// the command to fail
			seelog.Warnf("Add commands: update the last known IPv4 ip failed: %v", err)
		}
	}

	// Handle IPv6 if configured
	if ipamConf.HasIPv6() {
		err := verifyGatewayV6(ipamConf.IPV6Gateway, ipManager)
		if err != nil {
			return err
		}

		ipv6, err := getIPV6Address(ipManager, ipamConf)
		if err != nil {
			return err
		}
		ipv6Result = ipv6

		err = ipManager.Update(ipstore.LastKnownIPv6Key, ipv6.IP.String())
		if err != nil {
			// This error will only impact how the next ip will be found, it shouldn't cause
			// the command to fail
			seelog.Warnf("Add commands: update the last known IPv6 ip failed: %v", err)
		}
	}

	result, err := constructResults(ipamConf, ipv4Result, ipv6Result)
	if err != nil {
		return err
	}
	return types.PrintResult(result, cniVersion)
}

// Del will release one ip address and update the last known ip
func Del(args *skel.CmdArgs) error {
	defer seelog.Flush()
	ipamConf, _, err := config.LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	if err := validateDelConfiguration(ipamConf); err != nil {
		return err
	}

	dbConf, err := config.LoadDBConfig()
	if err != nil {
		return err
	}

	// Create the ip manager with dual-stack support
	var subnetV4, subnetV6 *net.IPNet
	if ipamConf.HasIPv4() {
		subnetV4 = &net.IPNet{
			IP:   ipamConf.IPV4Subnet.IP,
			Mask: ipamConf.IPV4Subnet.Mask,
		}
	}
	if ipamConf.HasIPv6() {
		subnetV6 = &net.IPNet{
			IP:   ipamConf.IPV6Subnet.IP,
			Mask: ipamConf.IPV6Subnet.Mask,
		}
	}

	ipManager, err := ipstore.NewIPAllocatorDualStack(dbConf, subnetV4, subnetV6)
	if err != nil {
		return err
	}
	defer ipManager.Close()

	return del(ipManager, ipamConf)
}

// validateDelConfiguration checks the configuration for ipam del
// Requires either an ID or a valid IP address (IPv4 or IPv6) for deletion
func validateDelConfiguration(ipamConf *config.IPAMConfig) error {
	hasIPv4Address := ipamConf.IPV4Address.IP != nil && net.ParseIP(ipamConf.IPV4Address.IP.String()) != nil
	hasIPv6Address := ipamConf.IPV6Address.IP != nil && net.ParseIP(ipamConf.IPV6Address.IP.String()) != nil

	if ipamConf.ID == "" && !hasIPv4Address && !hasIPv6Address {
		return errors.New("del commands: ip address (ipv4 or ipv6) and id can not all be empty for deletion")
	}
	return nil
}

func del(ipManager ipstore.IPAllocator, ipamConf *config.IPAMConfig) error {
	var releasedIPv4, releasedIPv6 string

	hasIPv4Address := ipamConf.IPV4Address.IP != nil && net.ParseIP(ipamConf.IPV4Address.IP.String()) != nil
	hasIPv6Address := ipamConf.IPV6Address.IP != nil && net.ParseIP(ipamConf.IPV6Address.IP.String()) != nil

	if hasIPv4Address || hasIPv6Address {
		// Release by explicit IP address(es)
		if hasIPv4Address {
			err := ipManager.Release(ipamConf.IPV4Address.IP.String())
			if err != nil {
				return err
			}
			releasedIPv4 = ipamConf.IPV4Address.IP.String()
		}

		if hasIPv6Address {
			// IPv6 addresses are stored with the "6" prefix in the database
			ipKey := ipstore.IPPrefixV6 + ipamConf.IPV6Address.IP.String()
			err := ipManager.Release(ipKey)
			if err != nil {
				return err
			}
			releasedIPv6 = ipamConf.IPV6Address.IP.String()
		}
	} else {
		// Release by unique id associated with the ip(s)
		ipv4, ipv6, err := ipManager.ReleaseByID(ipamConf.ID)
		if err != nil {
			return err
		}
		releasedIPv4 = ipv4
		releasedIPv6 = ipv6
	}

	// Update the last known IPv4 ip
	if releasedIPv4 != "" {
		err := ipManager.Update(config.LastKnownIPKey, releasedIPv4)
		if err != nil {
			// This error will only impact how the next ip will be found, it shouldn't cause
			// the command to fail
			seelog.Warnf("Del commands: update the last known IPv4 ip failed: %v", err)
		}
	}

	// Update the last known IPv6 ip
	if releasedIPv6 != "" {
		err := ipManager.Update(ipstore.LastKnownIPv6Key, releasedIPv6)
		if err != nil {
			// This error will only impact how the next ip will be found, it shouldn't cause
			// the command to fail
			seelog.Warnf("Del commands: update the last known IPv6 ip failed: %v", err)
		}
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
		err := ipManager.Assign(assignedAddress.IP.String(), conf.ID)
		if err != nil {
			return nil, errors.Wrapf(err, "getIPV4Address commands: failed to mark this ip %v as used", assignedAddress)
		}
	} else {
		// Get the next ip from db based on the last used ip
		nextIP, err := getIPV4AddressFromDB(ipManager, conf)
		if err != nil {
			return nil, err
		}
		assignedAddress.IP = net.ParseIP(nextIP)
		assignedAddress.Mask = conf.IPV4Subnet.Mask
	}
	return assignedAddress, nil
}

// getIPV4AddressFromDB will try to get an ipv4 address from the ipmanager
func getIPV4AddressFromDB(ipManager ipstore.IPAllocator, conf *config.IPAMConfig) (string, error) {
	startIP := conf.IPV4Subnet.IP.Mask(conf.IPV4Subnet.Mask)
	ok, err := ipManager.Exists(config.LastKnownIPKey)
	if err != nil {
		return "", errors.Wrap(err, "getIPV4AddressFromDB commands: failed to read the db")
	}
	if ok {
		lastKnownIPStr, err := ipManager.Get(config.LastKnownIPKey)
		if err != nil {
			return "", errors.Wrap(err, "getIPV4AddressFromDB commands: failed to get lask known ip from the db")
		}
		startIP = net.ParseIP(lastKnownIPStr)
	}

	ipManager.SetLastKnownIP(startIP)
	nextIP, err := ipManager.GetAvailableIP(conf.ID)
	if err != nil {
		return "", errors.Wrap(err, "getIPV4AddressFromDB commands: failed to get available ip from the db")
	}

	return nextIP, nil
}

// constructResults construct the struct from IPAM configuration to be used
// by bridge plugin. It accepts optional IPv4 and IPv6 results for dual-stack support.
func constructResults(conf *config.IPAMConfig, ipv4, ipv6 *net.IPNet) (*current.Result, error) {
	result := &current.Result{}

	if ipv4 != nil {
		if ipv4.IP.To4() == nil {
			return nil, errors.New("constructResults commands: invalid ipv4 address")
		}

		ipConfig := &current.IPConfig{
			Version: "4",
			Address: *ipv4,
			Gateway: conf.IPV4Gateway,
		}
		result.IPs = append(result.IPs, ipConfig)
		result.Routes = append(result.Routes, conf.IPV4Routes...)
	}

	if ipv6 != nil {
		// Verify it's a valid IPv6 address (not IPv4)
		if ipv6.IP.To4() != nil {
			return nil, errors.New("constructResults commands: invalid ipv6 address")
		}

		ipConfig := &current.IPConfig{
			Version: "6",
			Address: *ipv6,
			Gateway: conf.IPV6Gateway,
		}
		result.IPs = append(result.IPs, ipConfig)
		result.Routes = append(result.Routes, conf.IPV6Routes...)
	}

	if len(result.IPs) == 0 {
		return nil, errors.New("constructResults commands: no IP addresses configured")
	}

	return result, nil
}

// verifyGateway checks if this gateway address is the default gateway or used by other container
func verifyGateway(gw net.IP, ipManager ipstore.IPAllocator) error {
	// Check if gateway address has already been used and if it's used by gateway
	value, err := ipManager.Get(gw.String())
	if err != nil {
		return errors.Wrap(err, "verifyGateway commands: failed to get the value of gateway")
	}
	if value == "" {
		// Address not used, mark it as used
		err := ipManager.Assign(gw.String(), config.GatewayValue)
		if err != nil {
			return errors.Wrap(err, "verifyGateway commands: failed to update gateway into the db")
		}
	} else if value == config.GatewayValue {
		// Address is used by gateway
		return nil
	} else {
		return errors.New("verifyGateway commands: ip of gateway has already been used")
	}

	return nil
}

// getIPV6Address returns the available IPv6 address from configuration if specified or from the
// db if not explicitly specified in the configuration
func getIPV6Address(ipManager ipstore.IPAllocator, conf *config.IPAMConfig) (*net.IPNet, error) {
	assignedAddress := &net.IPNet{
		IP:   conf.IPV6Address.IP,
		Mask: conf.IPV6Address.Mask,
	}
	if assignedAddress.IP != nil {
		// IP was specified in the configuration, try to assign this ip as used
		// if this ip has already been used, it will return an error
		// IPv6 addresses are stored with the "6" prefix in the database
		ipKey := ipstore.IPPrefixV6 + assignedAddress.IP.String()
		err := ipManager.Assign(ipKey, conf.ID)
		if err != nil {
			return nil, errors.Wrapf(err, "getIPV6Address commands: failed to mark this ip %v as used", assignedAddress)
		}
	} else {
		// Get the next ip from db based on the last used ip
		nextIP, err := getIPV6AddressFromDB(ipManager, conf)
		if err != nil {
			return nil, err
		}
		assignedAddress.IP = net.ParseIP(nextIP)
		assignedAddress.Mask = conf.IPV6Subnet.Mask
	}
	return assignedAddress, nil
}

// getIPV6AddressFromDB will try to get an IPv6 address from the ipmanager
func getIPV6AddressFromDB(ipManager ipstore.IPAllocator, conf *config.IPAMConfig) (string, error) {
	startIP := conf.IPV6Subnet.IP.Mask(conf.IPV6Subnet.Mask)
	// Ensure it's 16 bytes for IPv6
	if len(startIP) != 16 {
		startIP = startIP.To16()
	}

	ok, err := ipManager.Exists(ipstore.LastKnownIPv6Key)
	if err != nil {
		return "", errors.Wrap(err, "getIPV6AddressFromDB commands: failed to read the db")
	}
	if ok {
		lastKnownIPStr, err := ipManager.Get(ipstore.LastKnownIPv6Key)
		if err != nil {
			return "", errors.Wrap(err, "getIPV6AddressFromDB commands: failed to get last known IPv6 ip from the db")
		}
		startIP = net.ParseIP(lastKnownIPStr)
	}

	ipManager.SetLastKnownIPv6(startIP)
	nextIP, err := ipManager.GetAvailableIPv6(conf.ID)
	if err != nil {
		return "", errors.Wrap(err, "getIPV6AddressFromDB commands: failed to get available IPv6 ip from the db")
	}

	return nextIP, nil
}

// verifyGatewayV6 checks if this IPv6 gateway address is the default gateway or used by other container
func verifyGatewayV6(gw net.IP, ipManager ipstore.IPAllocator) error {
	// IPv6 gateways are stored with the "6" prefix in the database
	gwKey := ipstore.IPPrefixV6 + gw.String()

	// Check if gateway address has already been used and if it's used by gateway
	value, err := ipManager.Get(gwKey)
	if err != nil {
		return errors.Wrap(err, "verifyGatewayV6 commands: failed to get the value of IPv6 gateway")
	}
	if value == "" {
		// Address not used, mark it as used with IPv6-specific gateway ID
		err := ipManager.Assign(gwKey, config.GatewayV6Value)
		if err != nil {
			return errors.Wrap(err, "verifyGatewayV6 commands: failed to update IPv6 gateway into the db")
		}
	} else if value == config.GatewayV6Value {
		// Address is used by IPv6 gateway
		return nil
	} else {
		return errors.New("verifyGatewayV6 commands: ip of IPv6 gateway has already been used")
	}

	return nil
}
