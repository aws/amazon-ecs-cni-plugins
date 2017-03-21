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

package config

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/pkg/errors"
)

const (
	EnvDBName                = "IPAM_DB_NAME"
	EnvBucketName            = "IPAM_BUCKET_NAME"
	EnvIpamTimeout           = "IPAM_TIMEOUT"
	LastKnownIPKey           = "lastKnownIP"
	GatewayValue             = "GateWay"
	DefaultConnectionTimeout = 5 * time.Second
)

// IPAMConfig represents the IP related network configuration
type IPAMConfig struct {
	types.CommonArgs
	Type        string         `json:"type,omitempty"`
	IPV4Subnet  types.IPNet    `json:"ipv4-subnet,omitempty"`
	IPV4Address types.IPNet    `json:"ipv4-address,omitempty"`
	IPV4Gateway net.IP         `json:"ipv4-gateway,omitempty"`
	Routes      []*types.Route `json:"routes,omitempty"`
	DB          string         `json:"db,omitempty"`
	Bucket      string         `json:"bucket,omitempty"`
	Timeout     string         `json:"timeout,omitempty"`
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
	conf := &Conf{}
	if err := json.Unmarshal(bytes, &conf); err != nil {
		return nil, "", errors.Wrapf(err, "LoadIPAMConfig config: 'failed to load netconf")
	}
	if conf.IPAM == nil {
		return nil, "", errors.New("LoadIPAMConfig config: 'IPAM' field missing in configuration")
	}

	if err := types.LoadArgs(args, conf.IPAM); err != nil {
		return nil, "", errors.Wrapf(err, "LoadIPAMConfig config: failed to parse args: %v", args)
	}

	// subnet is required to allocate ip address
	if conf.IPAM.IPV4Subnet.IP == nil || conf.IPAM.IPV4Subnet.Mask == nil {
		return nil, "", errors.New("LoadIPAMConfig config: subnet is required")
	}
	if ones, _ := conf.IPAM.IPV4Subnet.Mask.Size(); ones > 30 {
		return nil, "", errors.New("LoadIPAMConfig config: no available ip with mask beyond 31 in the subnet")
	}

	// Validate the ip if specified explicitly
	if conf.IPAM.IPV4Address.IP != nil {
		err := verifyIPSubnet(conf.IPAM.IPV4Address.IP,
			net.IPNet{
				IP:   conf.IPAM.IPV4Subnet.IP,
				Mask: conf.IPAM.IPV4Subnet.Mask})
		if err != nil {
			return nil, "", err
		}
	}

	// get the default gateway
	if conf.IPAM.IPV4Gateway == nil {
		conf.IPAM.IPV4Gateway = getDefaultIPV4GW(conf.IPAM.IPV4Subnet)
	}

	db := os.Getenv(EnvDBName)
	if len(strings.TrimSpace(db)) == 0 {
		return nil, "", errors.Errorf("LoadIPAMConfig config: IPAM DB path is not set")
	}
	conf.IPAM.DB = db

	bucket := os.Getenv(EnvBucketName)
	if len(strings.TrimSpace(bucket)) == 0 {
		return nil, "", errors.Errorf("LoadIPAMConfig config: IPAM Bucket name is not set")
	}
	conf.IPAM.Bucket = bucket

	dbTimeout := os.Getenv(EnvIpamTimeout)
	if len(strings.TrimSpace(dbTimeout)) != 0 {
		conf.IPAM.Timeout = dbTimeout
	}

	return conf.IPAM, conf.CNIVersion, nil
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
