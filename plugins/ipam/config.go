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
	"encoding/json"
	"net"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/pkg/errors"
)

const SupportedVersions = ""

// IPAMConfig represents the IP related network configuration
type IPAMConfig struct {
	types.CommonArgs
	Type      string         `json:"type,omitempty"`
	Subnet    types.IPNet    `json:"subnet,omitempty"`
	IPAddress types.IPNet    `json:"ipAddress,omitempty"`
	Gateway   net.IP         `json:"gateway,omitempty"`
	Routes    []*types.Route `json:"routes,omitempty"`
}

// Net loads the option from configuration file
type Conf struct {
	Name       string      `json:"name,omitempty"`
	CNIVersion string      `json:"cniVersion,omitempty"`
	IPAM       *IPAMConfig `json:"ipam"`
}

// LoadIPAMConfig loads the IPAM configuration from the input bytes
// bytes: Configuration read from os.stdin
// args: Configuration read from environment variable "CNI_ARGS"
func LoadIPAMConfig(bytes []byte, args string) (*IPAMConfig, string, error) {
	conf := &Conf{}
	if err := json.Unmarshal(bytes, &conf); err != nil {
		return nil, "", errors.Wrapf(err, "failed to load netconf")
	}

	if conf.IPAM == nil {
		return nil, conf.CNIVersion, errors.New("IPAM field missing in configuration")
	}

	if err := types.LoadArgs(args, conf.IPAM); err != nil {
		return nil, conf.CNIVersion, errors.Wrapf(err, "failed to parse args: %v", args)
	}

	return conf.IPAM, conf.CNIVersion, nil
}
