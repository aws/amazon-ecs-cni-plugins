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

package capabilities

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
)

const (
	// Command is the option for the plugin to print version
	Command = "capabilities"
	// TaskENICapability is the capability to support basic task-eni network mode
	TaskENICapability = "awsvpc-network-mode"
)

// Capability indicates the capability of a plugin
type Capability struct {
	Capabilities []string `json:"capabilities,omitempty"`
}

// New returns a Capability object with specified capabilities
func New(capabilities ...string) *Capability {
	return &Capability{
		Capabilities: capabilities,
	}
}

// String returns the JSON string of the Capability struct
func (cap *Capability) String() (string, error) {
	data, err := json.Marshal(cap)
	if err != nil {
		return "", errors.Wrapf(err, "capabilities: failed to marshal capabilities info: %v", cap.Capabilities)
	}

	return string(data), nil
}

// Print writes the supported capabilities info into the stdout
func (cap *Capability) Print() error {
	info, err := cap.String()
	if err != nil {
		return err
	}

	fmt.Println(info)
	return nil
}
