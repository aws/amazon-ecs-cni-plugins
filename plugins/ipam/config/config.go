// Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "license"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package config

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"time"

	"github.com/aws/amazon-ecs-cni-plugins/plugins/ipam/ipstore"
	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/pkg/errors"
)

const (
	EnvDBPath                = "IPAM_DB_PATH"
	EnvIpamTimeout           = "IPAM_DB_CONNECTION_TIMEOUT"
	LastKnownIPKey           = "lastKnownIP"
	LastKnownIPv4Key         = "lastKnownIPv4"
	GatewayValue             = "GateWay"
	GatewayV6Value           = "GateWayV6"
	DefaultDBPath            = "/data/eni-ipam.db"
	BucketName               = "IPAM"
	DefaultConnectionTimeout = 5 * time.Second
)

// IPAMConfig represents the IP related network configuration
type IPAMConfig struct {
	types.CommonArgs
	Type string `json:"type,omitempty"`

	// IPv4 fields (existing)
	IPV4Subnet  types.IPNet    `json:"ipv4-subnet,omitempty"`
	IPV4Address types.IPNet    `json:"ipv4-address,omitempty"`
	IPV4Gateway net.IP         `json:"ipv4-gateway,omitempty"`
	IPV4Routes  []*types.Route `json:"ipv4-routes,omitempty"`

	// IPv6 fields (new)
	IPV6Subnet  types.IPNet    `json:"ipv6-subnet,omitempty"`
	IPV6Address types.IPNet    `json:"ipv6-address,omitempty"`
	IPV6Gateway net.IP         `json:"ipv6-gateway,omitempty"`
	IPV6Routes  []*types.Route `json:"ipv6-routes,omitempty"`

	ID string `json:"id,omitempty"`
}

// HasIPv4 returns true if IPv4 subnet is configured
func (c *IPAMConfig) HasIPv4() bool {
	return c.IPV4Subnet.IP != nil && c.IPV4Subnet.Mask != nil
}

// HasIPv6 returns true if IPv6 subnet is configured
func (c *IPAMConfig) HasIPv6() bool {
	return c.IPV6Subnet.IP != nil && c.IPV6Subnet.Mask != nil
}

// Conf stores the option from configuration file
type Conf struct {
	Name       string      `json:"name,omitempty"`
	CNIVersion string      `json:"cniVersion,omitempty"`
	IPAM       *IPAMConfig `json:"ipam"`
}

// LoadIPAMConfig loads the IPAM configuration from the input bytes and validates the parameter
// bytes: Configuration read from os.stdin
// args: Configuration read from environment variable "CNI_ARGS"
func LoadIPAMConfig(bytes []byte, args string) (*IPAMConfig, string, error) {
	ipamConf := &Conf{}

	if err := json.Unmarshal(bytes, &ipamConf); err != nil {
		return nil, "", errors.Wrapf(err, "loadIPAMConfig config: failed to load netconf, %s", string(bytes))
	}
	if ipamConf.IPAM == nil {
		return nil, "", errors.New("loadIPAMConfig config: 'IPAM' field missing in configuration: " + string(bytes))
	}

	hasIPv4 := ipamConf.IPAM.IPV4Subnet.IP != nil && ipamConf.IPAM.IPV4Subnet.Mask != nil
	hasIPv6 := ipamConf.IPAM.IPV6Subnet.IP != nil && ipamConf.IPAM.IPV6Subnet.Mask != nil

	// At least one subnet (IPv4 or IPv6) is required
	if !hasIPv4 && !hasIPv6 {
		return nil, "", errors.New("loadIPAMConfig config: at least one subnet (ipv4 or ipv6) is required")
	}

	// Validate IPv4 configuration if present
	if hasIPv4 {
		if ones, _ := ipamConf.IPAM.IPV4Subnet.Mask.Size(); ones > ipstore.MaxMask {
			return nil, "", errors.New("loadIPAMConfig config: no available ip in the subnet")
		}

		// convert from types.IPNet to net.IPNet
		subnet := net.IPNet{
			IP:   ipamConf.IPAM.IPV4Subnet.IP,
			Mask: ipamConf.IPAM.IPV4Subnet.Mask,
		}

		// Validate the ip if specified explicitly
		if ipamConf.IPAM.IPV4Address.IP != nil {
			err := verifyIPSubnet(ipamConf.IPAM.IPV4Address.IP, subnet)
			if err != nil {
				return nil, "", err
			}
			if isNetworkOrBroadcast(subnet, ipamConf.IPAM.IPV4Address.IP) {
				return nil, "", errors.Errorf("ip specified is reserved by default: %v", ipamConf.IPAM.IPV4Address)
			}
		}

		// get the default gateway
		if ipamConf.IPAM.IPV4Gateway == nil {
			ipamConf.IPAM.IPV4Gateway = getDefaultIPV4GW(ipamConf.IPAM.IPV4Subnet)
		} else {
			if isNetworkOrBroadcast(subnet, ipamConf.IPAM.IPV4Gateway) {
				return nil, "", errors.Errorf("gateway specified is reserved by default: %v", ipamConf.IPAM.IPV4Gateway)
			}
			if err := verifyIPSubnet(ipamConf.IPAM.IPV4Gateway, subnet); err != nil {
				return nil, "", err
			}
		}
	}

	// Validate IPv6 configuration if present
	if hasIPv6 {
		// Validate IPv6 subnet prefix length (0-128)
		ones, bits := ipamConf.IPAM.IPV6Subnet.Mask.Size()
		if bits != 128 {
			return nil, "", errors.Errorf("loadIPAMConfig config: invalid ipv6 subnet: %v", ipamConf.IPAM.IPV6Subnet)
		}
		if ones > ipstore.MaxMaskIPv6 {
			return nil, "", errors.New("loadIPAMConfig config: no available ip in the subnet")
		}

		// convert from types.IPNet to net.IPNet
		subnetV6 := net.IPNet{
			IP:   ipamConf.IPAM.IPV6Subnet.IP,
			Mask: ipamConf.IPAM.IPV6Subnet.Mask,
		}

		// Validate the IPv6 address if specified explicitly
		if ipamConf.IPAM.IPV6Address.IP != nil {
			// Validate it's a valid 128-bit IPv6 address
			if ipamConf.IPAM.IPV6Address.IP.To4() != nil {
				return nil, "", errors.Errorf("loadIPAMConfig config: invalid ipv6 address: %v", ipamConf.IPAM.IPV6Address.IP)
			}
			if ipamConf.IPAM.IPV6Address.IP.To16() == nil {
				return nil, "", errors.Errorf("loadIPAMConfig config: invalid ipv6 address: %v", ipamConf.IPAM.IPV6Address.IP)
			}

			// Validate address is within subnet
			err := verifyIPSubnet(ipamConf.IPAM.IPV6Address.IP, subnetV6)
			if err != nil {
				return nil, "", err
			}

			// Reject network address (IPv6 has no broadcast)
			if isIPv6NetworkAddress(subnetV6, ipamConf.IPAM.IPV6Address.IP) {
				return nil, "", errors.Errorf("loadIPAMConfig config: ip specified is the network address: %v", ipamConf.IPAM.IPV6Address.IP)
			}
		}

		// Get the default IPv6 gateway or validate the specified one
		if ipamConf.IPAM.IPV6Gateway == nil {
			ipamConf.IPAM.IPV6Gateway = getDefaultIPV6GW(ipamConf.IPAM.IPV6Subnet)
		} else {
			// Validate it's a valid 128-bit IPv6 address
			if ipamConf.IPAM.IPV6Gateway.To4() != nil {
				return nil, "", errors.Errorf("loadIPAMConfig config: invalid ipv6 gateway: %v", ipamConf.IPAM.IPV6Gateway)
			}
			if ipamConf.IPAM.IPV6Gateway.To16() == nil {
				return nil, "", errors.Errorf("loadIPAMConfig config: invalid ipv6 gateway: %v", ipamConf.IPAM.IPV6Gateway)
			}

			// Validate gateway is within subnet
			if err := verifyIPSubnet(ipamConf.IPAM.IPV6Gateway, subnetV6); err != nil {
				return nil, "", err
			}

			// Reject network address as gateway
			if isIPv6NetworkAddress(subnetV6, ipamConf.IPAM.IPV6Gateway) {
				return nil, "", errors.Errorf("loadIPAMConfig config: gateway specified is the network address: %v", ipamConf.IPAM.IPV6Gateway)
			}
		}
	}

	return ipamConf.IPAM, ipamConf.CNIVersion, nil
}

// LoadDBConfig will read the configuration of db from environment variable
func LoadDBConfig() (*ipstore.Config, error) {
	dbConf := &ipstore.Config{PersistConnection: true}

	db := os.Getenv(EnvDBPath)
	if len(strings.TrimSpace(db)) == 0 {
		db = DefaultDBPath
	}
	dbConf.DB = db
	dbConf.Bucket = BucketName

	dbTimeoutStr := os.Getenv(EnvIpamTimeout)
	if len(strings.TrimSpace(dbTimeoutStr)) == 0 {
		dbConf.ConnectionTimeout = DefaultConnectionTimeout
	} else {
		duration, err := time.ParseDuration(dbTimeoutStr)
		if err != nil {
			return nil, errors.Errorf("loadDBConfig config: parsing timeout string failed: %v", duration)
		}
		dbConf.ConnectionTimeout = duration
	}

	return dbConf, nil
}

// verifyIPSubnet check if the ip is within the subnet
func verifyIPSubnet(ip net.IP, subnet net.IPNet) error {
	if !subnet.Contains(ip) {
		return errors.Errorf("verifyIPSubnet config: ip %v is not within the subnet %v", ip, subnet)
	}

	return nil
}

// getDefaultGW returns the first ip address in the subnet as the gateway
func getDefaultIPV4GW(subnet types.IPNet) net.IP {
	return ip.NextIP(subnet.IP)
}

// isNetworkOrBroadcast checks whether the ip is the network address or broadcast address of the subnet
func isNetworkOrBroadcast(subnet net.IPNet, ip net.IP) bool {
	network := subnet.IP.Mask(subnet.Mask)
	broadcast := net.IP(make([]byte, 4))
	for i := 0; i < 4; i++ {
		broadcast[i] = network[i] | ^subnet.Mask[i]
	}

	if ip.Equal(network) || ip.Equal(broadcast) {
		return true
	}
	return false
}

// getDefaultIPV6GW returns the first usable address in the IPv6 subnet (network address + 1)
func getDefaultIPV6GW(subnet types.IPNet) net.IP {
	return ip.NextIP(subnet.IP)
}

// isIPv6NetworkAddress checks if the IP is the network address of the IPv6 subnet
// IPv6 does not have broadcast addresses, so we only check for network address
func isIPv6NetworkAddress(subnet net.IPNet, ipAddr net.IP) bool {
	network := subnet.IP.Mask(subnet.Mask)
	return ipAddr.Equal(network)
}

// isIPv4 returns true if the IP is an IPv4 address
func isIPv4(ipAddr net.IP) bool {
	if ipAddr == nil {
		return false
	}
	return ipAddr.To4() != nil
}

// isIPv6 returns true if the IP is an IPv6 address (and not an IPv4 address)
func isIPv6(ipAddr net.IP) bool {
	if ipAddr == nil {
		return false
	}
	// To16() returns non-nil for both IPv4 and IPv6, so we need to check
	// that it's not an IPv4 address first
	return ipAddr.To4() == nil && ipAddr.To16() != nil
}
