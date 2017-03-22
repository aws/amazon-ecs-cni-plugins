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
	EnvDBName                = "IPAM_DB_PATH"
	EnvIpamTimeout           = "IPAM_DB_CONNECTION_TIMEOUT"
	LastKnownIPKey           = "lastKnownIP"
	GatewayValue             = "GateWay"
	DefaultDBPath            = "/var/lib/ecs/data/ipam"
	BucketName               = "IPAM"
	DefaultConnectionTimeout = 5 * time.Second
)

// IPAMConfig represents the IP related network configuration
type IPAMConfig struct {
	types.CommonArgs
	Type        string         `json:"type,omitempty"`
	IPV4Subnet  types.IPNet    `json:"ipv4-subnet,omitempty"`
	IPV4Address types.IPNet    `json:"ipv4-address,omitempty"`
	IPV4Gateway net.IP         `json:"ipv4-gateway,omitempty"`
	IPV4Routes  []*types.Route `json:"ipv4-routes,omitempty"`
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
		return nil, "", errors.Wrapf(err, "loadIPAMConfig config: 'failed to load netconf")
	}
	if ipamConf.IPAM == nil {
		return nil, "", errors.New("loadIPAMConfig config: 'IPAM' field missing in configuration")
	}

	if err := types.LoadArgs(args, ipamConf.IPAM); err != nil {
		return nil, "", errors.Wrapf(err, "loadIPAMConfig config: failed to parse args: %v", args)
	}

	// subnet is required to allocate ip address
	if ipamConf.IPAM.IPV4Subnet.IP == nil || ipamConf.IPAM.IPV4Subnet.Mask == nil {
		return nil, "", errors.New("loadIPAMConfig config: subnet is required")
	}
	if ones, _ := ipamConf.IPAM.IPV4Subnet.Mask.Size(); ones > 30 {
		return nil, "", errors.New("loadIPAMConfig config: no available ip with mask beyond 31 in the subnet")
	}

	// Validate the ip if specified explicitly
	if ipamConf.IPAM.IPV4Address.IP != nil {
		err := verifyIPSubnet(ipamConf.IPAM.IPV4Address.IP,
			net.IPNet{
				IP:   ipamConf.IPAM.IPV4Subnet.IP,
				Mask: ipamConf.IPAM.IPV4Subnet.Mask})
		if err != nil {
			return nil, "", err
		}
	}

	// get the default gateway
	if ipamConf.IPAM.IPV4Gateway == nil {
		ipamConf.IPAM.IPV4Gateway = getDefaultIPV4GW(ipamConf.IPAM.IPV4Subnet)
	}

	return ipamConf.IPAM, ipamConf.CNIVersion, nil
}

func LoadDBConfig() (*ipstore.Config, error) {
	dbConf := &ipstore.Config{PersistConnection: true}

	db := os.Getenv(EnvDBName)
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
