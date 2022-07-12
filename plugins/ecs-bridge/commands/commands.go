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

// Add invokes the command to create the bridge add the veth pair to
// connect container's namespace with the bridge
func Add(args *skel.CmdArgs) error {
	defer log.Flush()
	err := add(args, engine.New())
	if err != nil {
		log.Errorf("Error executing ADD command: %v", err)
	}

	return err
}

// Del invokes the command to tear down the bridge and the veth pair
func Del(args *skel.CmdArgs) error {
	defer log.Flush()
	err := del(args, engine.New())
	if err != nil {
		log.Errorf("Error executing DEL command: %v", err)
	}

	return err
}

func detailLog(msg string, args *skel.CmdArgs, conf *types.NetConf, hostVethName string) {
	var ipamType string
	if conf != nil {
		ipamType = conf.IPAM.Type
	}
	msg = fmt.Sprintf("msg=\"%s\" netns=%s ifname=%s bridgeName=%s containerID=%s",
		msg, args.Netns, args.IfName, conf.BridgeName, args.ContainerID)
	if ipamType != "" {
		msg = msg + " ipamType=" + ipamType
	}
	if hostVethName != "" {
		msg = msg + " hostVethName=" + hostVethName
	}
	log.Infof(msg)
}

func add(args *skel.CmdArgs, engine engine.Engine) error {
	conf, err := types.NewConf(args)
	if err != nil {
		return err
	}

	detailLog("Creating the bridge", args, conf, "")
	bridge, err := engine.CreateBridge(conf.BridgeName, conf.MTU)
	if err != nil {
		return err
	}

	detailLog("Creating veth pair for namespace", args, conf, "")
	containerVethInterface, hostVethName, err := engine.CreateVethPair(
		args.Netns, conf.MTU, args.IfName)
	if err != nil {
		return err
	}

	detailLog("Attaching veth pair to bridge", args, conf, hostVethName)
	hostVethInterface, err := engine.AttachHostVethInterfaceToBridge(hostVethName, bridge)
	if err != nil {
		return err
	}

	detailLog("Running IPAM plugin ADD", args, conf, hostVethName)
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

	detailLog("Configuring container's interface", args, conf, hostVethName)
	err = engine.ConfigureContainerVethInterface(args.Netns, result, args.IfName)
	if err != nil {
		return err
	}

	detailLog("Configuring bridge", args, conf, hostVethName)
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
	detailLog("Deleting veth interface", args, conf, "")

	if utils.ZeroOrNil(conf.IPAM) {
		detailLog("IPAM configuration not found, skip DEL for IPAM", args, conf, "")
		return nil
	}

	detailLog("Running IPAM plugin DEL", args, conf, "")
	err = engine.RunIPAMPluginDel(conf.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}

	detailLog("Deleting container interface", args, conf, "")
	return engine.DeleteVeth(args.Netns, args.IfName)
}
