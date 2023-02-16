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
	"fmt"

	"github.com/aws/amazon-ecs-cni-plugins/pkg/utils"
	"github.com/aws/amazon-ecs-cni-plugins/plugins/ecs-bridge/engine"
	"github.com/aws/amazon-ecs-cni-plugins/plugins/ecs-bridge/types"

	log "github.com/cihub/seelog"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
)

func detailLogMsg(msg string, args *skel.CmdArgs, conf *types.NetConf, hostVethName string) string {
	var ipamType string
	var bridgeName string
	if conf != nil {
		ipamType = conf.IPAM.Type
		bridgeName = conf.BridgeName
	}
	msg = fmt.Sprintf("msg=\"%s\" netns=%s ifname=%s containerID=%s",
		msg, args.Netns, args.IfName, args.ContainerID)
	if bridgeName != "" {
		msg = msg + " bridgeName=" + bridgeName
	}
	if ipamType != "" {
		msg = msg + " ipamType=" + ipamType
	}
	if hostVethName != "" {
		msg = msg + " hostVethName=" + hostVethName
	}
	return msg
}

func detailLogError(msg string, args *skel.CmdArgs, conf *types.NetConf, hostVethName string) {
	msg = detailLogMsg(msg, args, conf, hostVethName)
	log.Error(msg)
}

func detailLogInfo(msg string, args *skel.CmdArgs, conf *types.NetConf, hostVethName string) {
	msg = detailLogMsg(msg, args, conf, hostVethName)
	log.Info(msg)
}

// Add invokes the command to create the bridge add the veth pair to
// connect container's namespace with the bridge
func Add(args *skel.CmdArgs) error {
	defer log.Flush()
	err := add(args, engine.New())
	if err != nil {
		detailLogError("Error executing ADD command: "+err.Error(), args, nil, "")
	}

	return err
}

// Del invokes the command to tear down the bridge and the veth pair
func Del(args *skel.CmdArgs) error {
	defer log.Flush()
	err := del(args, engine.New())
	if err != nil {
		detailLogError("Error executing DEL command: "+err.Error(), args, nil, "")
	}

	return err
}

func add(args *skel.CmdArgs, engine engine.Engine) error {
	conf, err := types.NewConf(args)
	if err != nil {
		return err
	}

	detailLogInfo("Creating the bridge", args, conf, "")
	bridge, err := engine.CreateBridge(conf.BridgeName, conf.MTU)
	if err != nil {
		return err
	}

	detailLogInfo("Creating veth pair for namespace", args, conf, "")
	containerVethInterface, hostVethName, err := engine.CreateVethPair(
		args.Netns, conf.MTU, args.IfName)
	if err != nil {
		return err
	}

	detailLogInfo("Attaching veth pair to bridge", args, conf, hostVethName)
	hostVethInterface, err := engine.AttachHostVethInterfaceToBridge(hostVethName, bridge)
	if err != nil {
		return err
	}

	detailLogInfo("Running IPAM plugin ADD", args, conf, hostVethName)
	result, err := engine.RunIPAMPluginAdd(conf.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}

	// Construct the Interfaces list for the result returned from the IPAM
	// plugin. This consists of all the interfaces we know about. This
	// includes the bridge, the two ends of the veth interface created
	result.Interfaces = []*current.Interface{
		// the bridge interface
		0: &current.Interface{
			Name: bridge.Attrs().Name,
			Mac:  bridge.Attrs().HardwareAddr.String(),
		},
		// the host veth interface
		1: hostVethInterface,
		// the container veth interface
		2: containerVethInterface,
	}

	// Set the index for the container veth interface in the `Interfaces`
	// list populated above.
	// The `ipam.ConfigureIface` method needs this index to be set as it
	// needs to know which interface should be used when adding routes
	result.IPs[0].Interface = 2

	detailLogInfo("Configuring container's interface", args, conf, hostVethName)
	err = engine.ConfigureContainerVethInterface(args.Netns, result, args.IfName)
	if err != nil {
		return err
	}

	detailLogInfo("Configuring bridge", args, conf, hostVethName)
	err = engine.ConfigureBridge(result, bridge)
	if err != nil {
		return err
	}
	return result.Print()
}

func del(args *skel.CmdArgs, engine engine.Engine) error {
	conf, err := types.NewConf(args)
	if err != nil {
		return err
	}
	detailLogInfo("Deleting veth interface", args, conf, "")

	if utils.ZeroOrNil(conf.IPAM) {
		detailLogInfo("IPAM configuration not found, skip DEL for IPAM", args, conf, "")
	} else {
		detailLogInfo("Running IPAM plugin DEL", args, conf, "")
		err = engine.RunIPAMPluginDel(conf.IPAM.Type, args.StdinData)
		if err != nil {
			detailLogError("Error running IPAM plugin DEL: "+err.Error(), args, conf, "")
		}
	}

	detailLogInfo("Deleting container interface", args, conf, "")
	return engine.DeleteVeth(args.Netns, args.IfName)
}
