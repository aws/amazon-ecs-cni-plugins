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
	"github.com/aws/amazon-ecs-cni-plugins/plugins/ipam/version/cnispec"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
)

func main() {
	skel.PluginMain(cmdAdd, cmdDel, cnispec.GetSpecVersionSupported())
}

// cmdAdd will return ip, gateway, routes which can be
// used in bridge plugin to configure veth pair and bridge
func cmdAdd(args *skel.CmdArgs) error {
	result, cniVersion, err := config.LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	return types.PrintResult(result, cniVersion)
}

// cmdDel won't be used, so just return
func cmdDel(args *skel.CmdArgs) error {
	return nil
}
