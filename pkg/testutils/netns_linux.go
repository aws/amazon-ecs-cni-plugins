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

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// netNsMountPath specifies the filesystem directory where netns are mounted.
const netNsMountPath = "/var/run/netns"

// netNS represent a Linux network namespace.
type netNS struct {
	file    *os.File
	mounted bool
	closed  bool
}

// NewNetNS creates a new netNS object.
func NewNetNS(name string) (NetNS, error) {
	err := os.MkdirAll(netNsMountPath, 0755)
	if err != nil {
		return nil, err
	}

	// Create the netns file to mount.
	nsPath := path.Join(netNsMountPath, name)
	fd, err := os.Create(nsPath)
	if err != nil {
		return nil, err
	}
	fd.Close()

	// Do namespace work in a dedicated goroutine, so that we can safely
	// Lock/Unlock OSThread without upsetting the state of this function.
	var wg sync.WaitGroup
	wg.Add(1)

	go (func() {
		defer wg.Done()
		runtime.LockOSThread()

		var origNS NetNS
		origNS, err = GetNetNSByPath(getCurrentThreadNetNSPath())
		if err != nil {
			return
		}
		defer origNS.Close()

		// Create a new netns on the current thread.
		err = unix.Unshare(unix.CLONE_NEWNET)
		if err != nil {
			return
		}
		defer origNS.Set()

		// Bind mount the new netns from the current thread onto the mount point.
		err = unix.Mount(getCurrentThreadNetNSPath(), nsPath, "none", unix.MS_BIND, "")
		if err != nil {
			return
		}

		fd, err = os.Open(nsPath)
		if err != nil {
			return
		}
	})()
	wg.Wait()

	if err != nil {
		unix.Unmount(nsPath, unix.MNT_DETACH)
		os.RemoveAll(nsPath)
		return nil, fmt.Errorf("failed to create namespace: %v", err)
	}

	return &netNS{file: fd, mounted: true}, nil
}

// GetNetNS creates a new netNS object representing an existing netns.
// Call the GetNetNSByName or GetNetNSByPath function directly if the input type is known.
func GetNetNS(nameOrPath string) (NetNS, error) {
	if strings.Contains(nameOrPath, "/") {
		return GetNetNSByPath(nameOrPath)
	} else {
		return GetNetNSByName(nameOrPath)
	}
}

// GetNetNSByName creates a new netNS object representing an existing netns by name.
func GetNetNSByName(name string) (NetNS, error) {
	if name == "" {
		return nil, fmt.Errorf("failed to get invalid netns %s", name)
	}
	return GetNetNSByPath(path.Join(netNsMountPath, name))
}

// GetNetNSByPath creates a new netNS object representing an existing netns by path.
func GetNetNSByPath(path string) (NetNS, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	return &netNS{file: fd, mounted: true}, nil
}

// Close releases the reference to the underlying netns.
func (ns *netNS) Close() error {
	if ns.closed {
		return fmt.Errorf("%s has already been closed", ns.file.Name())
	}

	err := ns.file.Close()
	if err != nil {
		return fmt.Errorf("Failed to close %s: %v", ns.file.Name(), err)
	}
	ns.closed = true

	if ns.mounted {
		err = unix.Unmount(ns.file.Name(), unix.MNT_DETACH)
		if err != nil {
			return fmt.Errorf("Failed to unmount namespace %s: %v", ns.file.Name(), err)
		}
		err = os.RemoveAll(ns.file.Name())
		if err != nil {
			return fmt.Errorf("Failed to clean up namespace %s: %v", ns.file.Name(), err)
		}
		ns.mounted = false
	}

	return nil
}

// GetFd returns a file descriptor for the underlying netns.
func (ns *netNS) GetFd() uintptr {
	return ns.file.Fd()
}

// GetPath returns the filesystem path for the underlying netns.
func (ns *netNS) GetPath() string {
	return ns.file.Name()
}

// Set sets the current thread's netns to the underlying netns.
func (ns *netNS) Set() error {
	if ns.closed {
		return fmt.Errorf("%s has already been closed", ns.file.Name())
	}

	err := unix.Setns(int(ns.GetFd()), unix.CLONE_NEWNET)
	if err != nil {
		return fmt.Errorf("Error switching to ns %v: %v", ns.file.Name(), err)
	}

	return nil
}

// Run runs the given function in the underlying netns.
func (ns *netNS) Run(toRun func() error) error {
	var err error

	if ns.closed {
		return fmt.Errorf("%s has already been closed", ns.file.Name())
	}

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		runtime.LockOSThread()
		var threadNS NetNS

		// Save the thread's current network namespace and
		// restore it after this go routine completes.
		threadNS, err = GetNetNSByPath(getCurrentThreadNetNSPath())
		if err != nil {
			err = fmt.Errorf("Failed to open current netns: %v", err)
			return
		}
		defer threadNS.Close()

		// Enter target namespace.
		if err = ns.Set(); err != nil {
			err = fmt.Errorf("Failed to enter netns %v: %v", ns.file.Name(), err)
			return
		}
		defer threadNS.Set()

		err = toRun()
	}()

	// Wait for the go routine to complete.
	wg.Wait()

	return err
}

// getCurrentThreadNetNSPath returns the path to the caller thread's netns.
func getCurrentThreadNetNSPath() string {
	return fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
}

