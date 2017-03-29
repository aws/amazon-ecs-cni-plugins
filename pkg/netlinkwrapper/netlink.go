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

package netlinkwrapper

import "github.com/vishvananda/netlink"

// NetLink wraps methods used from the vishvananda/netlink package
type NetLink interface {
	// LinkByName gets a link object given the device name
	LinkByName(name string) (netlink.Link, error)
	// LinkSetNsFd is equivalent to `ip link set $link netns $ns`
	LinkSetNsFd(link netlink.Link, fd int) error
	// ParseAddr parses an address string
	ParseAddr(s string) (*netlink.Addr, error)
	// AddrAdd is equivalent to `ip addr add $addr dev $link`
	AddrAdd(link netlink.Link, addr *netlink.Addr) error
	// LinkSetUp is equivalent to `ip link set $link up`
	LinkSetUp(link netlink.Link) error
	// LinkList is equivalent to: `ip link show`
	LinkList() ([]netlink.Link, error)
	// LinkSetDown is equivalent to: `ip link set $link down`
	LinkSetDown(link netlink.Link) error
	// RouteList gets a list of routes in the system.
	RouteList(link netlink.Link, family int) ([]netlink.Route, error)
}

type netLink struct {
}

// NewNetLink creates a new NetLink object
func NewNetLink() NetLink {
	return &netLink{}
}

func (*netLink) LinkByName(name string) (netlink.Link, error) {
	return netlink.LinkByName(name)
}

func (*netLink) LinkSetNsFd(link netlink.Link, fd int) error {
	return netlink.LinkSetNsFd(link, fd)
}

func (*netLink) ParseAddr(s string) (*netlink.Addr, error) {
	return netlink.ParseAddr(s)
}

func (*netLink) AddrAdd(link netlink.Link, addr *netlink.Addr) error {
	return netlink.AddrAdd(link, addr)
}

func (*netLink) LinkSetUp(link netlink.Link) error {
	return netlink.LinkSetUp(link)
}

func (*netLink) LinkList() ([]netlink.Link, error) {
	return netlink.LinkList()
}

func (*netLink) LinkSetDown(link netlink.Link) error {
	return netlink.LinkSetDown(link)
}

func (*netLink) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	return netlink.RouteList(link, family)
}
