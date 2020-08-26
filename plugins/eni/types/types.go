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

package types

import (
	"encoding/json"
	"net"

	log "github.com/cihub/seelog"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/pkg/errors"
)

// NetConf defines the parameters required to configure a contaner's namespace
// with an ENI
type NetConf struct {
	types.NetConf
	ENIID              string   `json:"eni"`
	MACAddress         string   `json:"mac"`
	IPAddresses        []string `json:"ip-addresses"`
	GatewayIPAddresses []string `json:"gateway-ip-addresses"`
	BlockIMDS          bool     `json:"block-instance-metadata"`
	StayDown           bool     `json:"stay-down"`
	MTU                int      `json:"mtu"`
}

// NewConf creates a new NetConf object by parsing the arguments supplied
func NewConf(args *skel.CmdArgs) (*NetConf, error) {
	var conf NetConf
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return nil, errors.Wrap(err, "newconf types: failed to parse config")
	}

	// Validate if all the required fields are present
	if conf.ENIID == "" {
		return nil, errors.Errorf("newconf types: missing required parameter in config: '%s'", "eni")
	}
	if conf.MACAddress == "" {
		return nil, errors.Errorf("newconf types: missing required parameter in config: '%s'", "mac")
	}
	if len(conf.IPAddresses) == 0 {
		return nil, errors.Errorf("newconf types: missing required parameter in config: '%s'", "ip-addresses")
	}

	// Validate if the mac address in the config is valid
	if _, err := net.ParseMAC(conf.MACAddress); err != nil {
		return nil, errors.Wrapf(err, "newconf types: malformatted mac address specified")
	}

	// Validate if the IP addresses in the config are valid
	for _, addr := range conf.IPAddresses {
		if err := isValidIPAddress(addr); err != nil {
			return nil, err
		}
	}

	// Validation complete. Return the parsed config object
	log.Debugf("Loaded config: %v", conf)
	return &conf, nil
}

func isValidIPAddress(address string) error {
	_, _, err := net.ParseCIDR(address)
	if err != nil {
		return errors.Errorf("newconf types: malformed IP address specified: %s", address)
	}

	return nil
}
