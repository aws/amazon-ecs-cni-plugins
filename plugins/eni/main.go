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
	"runtime"

	"github.com/aws/amazon-ecs-cni-plugins/plugins/eni/commands"
	log "github.com/cihub/seelog"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"
)

func init() {
	runtime.LockOSThread()
}

func main() {
	defer log.Flush()

	log.Info("eni plugin")
	skel.PluginMain(commands.Add, commands.Del, version.PluginSupports("0.2.0"))
}
