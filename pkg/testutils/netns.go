// Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package testutils

// NetNS represents a network namespace.
type NetNS interface {
	// GetFd returns a file descriptor for the underlying netns.
	GetFd() uintptr
	// Path returns the filesystem path representing the underlying netns.
	GetPath() string
	// Close releases the reference to the underlying netns.
	Close() error
	// Set sets the current thread's netns to the underlying netns.
	Set() error
	// Run runs the given function in the underlying netns.
	Run(toRun func() error) error
}

