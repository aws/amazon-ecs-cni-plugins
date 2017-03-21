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
	"github.com/aws/amazon-ecs-cni-plugins/plugins/ipam/config"
	"github.com/aws/amazon-ecs-cni-plugins/plugins/ipam/ipstore"
	"github.com/aws/amazon-ecs-cni-plugins/plugins/ipam/utils"
	"github.com/aws/amazon-ecs-cni-plugins/plugins/ipam/version/cnispec"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
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
	ipManager, err := ipstore.NewFromIPAM(conf)
	if err != nil {
		return err
	}
	defer ipManager.Close()

	err = utils.VerifyGateway(conf.IPV4Gateway, ipManager)
	if err != nil {
		return err
	}

	nextIP, err := utils.GetIPV4Address(ipManager, conf)
	if err != nil {
		return err
	}

	err = ipManager.Update(config.LastKnownIPKey, nextIP.IP.String())
	if err != nil {
		return err
	}

	return types.PrintResult(utils.ConstructResults(conf, *nextIP), cniVersion)
}

// cmdDel will release one ip address and update the last known ip
func cmdDel(args *skel.CmdArgs) error {
	conf, _, err := config.LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	// Create the ip manager
	ipManager, err := ipstore.NewFromIPAM(conf)
	if err != nil {
		return err
	}
	defer ipManager.Close()

	if conf.IPV4Address.IP == nil {
		return errors.New("cmdDel main: ip address is required for deletion")
	}

	ok, err := ipManager.Exists(conf.IPV4Address.IP.String())
	if err != nil {
		return err
	}
	if !ok {
		return errors.Errorf("cmdDel main: ip %v not existed in the db", conf.IPV4Address)
	}

	err = ipManager.Release(conf.IPV4Address.IP.String())
	if err != nil {
		return err
	}

	// Update the last known ip
	return ipManager.Update("lastKnownIP", conf.IPV4Address.IP.String())
}
