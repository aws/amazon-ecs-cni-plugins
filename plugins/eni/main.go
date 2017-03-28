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
	"flag"
	"fmt"
	"runtime"

	"github.com/aws/amazon-ecs-cni-plugins/pkg/logger"
	"github.com/aws/amazon-ecs-cni-plugins/pkg/version"
	"github.com/aws/amazon-ecs-cni-plugins/plugins/eni/commands"
	"github.com/aws/amazon-ecs-cni-plugins/plugins/eni/version/cnispec"
	log "github.com/cihub/seelog"
	"github.com/containernetworking/cni/pkg/skel"
)

const (
	defaultLogFilePath = "/var/log/ecs/ecs-cni-eni-plugin.log"
)

func init() {
	runtime.LockOSThread()
}

func setupLogger(loglevel string) {
	seelogLevel, ok := log.LogLevelFromString(loglevel)
	if !ok {
		seelogLevel = log.InfoLvl
	}
	fileWriter, err := log.NewFileWriter("/tmp/eni.log")
	if err != nil {
		log.Error(err)
		return
	}
	formatter, err := log.NewFormatter("%UTCDate(2006-01-02T15:04:05Z07:00) [%LEVEL] %Msg%n")
	if err != nil {
		log.Error(err)
		return
	}
	root, err := log.NewSplitDispatcher(formatter, []interface{}{fileWriter})
	if err != nil {
		log.Error(err)
		return
	}
	constraints, err := log.NewMinMaxConstraints(seelogLevel, log.CriticalLvl)
	if err != nil {
		log.Error(err)
		return
	}
	logger := log.NewAsyncLoopLogger(log.NewLoggerConfig(constraints, nil, root))
	log.ReplaceLogger(logger)
}

func main() {
	defer log.Flush()
	logger.SetupLogger(logger.GetLogFileLocation(defaultLogFilePath))

	var printVersion bool
	flag.BoolVar(&printVersion, "version", false, "prints version and exits")
	flag.Parse()

	if printVersion {
		printVersionInfo()
		return
	}

	setupLogger("debug")

	skel.PluginMain(commands.Add, commands.Del, cnispec.GetSpecVersionSupported())
}

func printVersionInfo() {
	versionInfo, err := version.String()
	if err != nil {
		fmt.Println("Error getting version string: ", err)
		return
	}
	fmt.Println(versionInfo)
}
