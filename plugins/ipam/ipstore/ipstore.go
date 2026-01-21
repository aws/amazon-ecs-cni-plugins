// Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package ipstore

import (
	"math/big"
	"net"
	"time"

	"github.com/docker/libkv/store"
	"github.com/docker/libkv/store/boltdb"
	"github.com/pkg/errors"
)

const (
	// Mask size beyond 30 won't be accepted since the .0 and .255 are reserved
	MaxMask = 30
	// MaxMaskIPv6 is the maximum prefix length for IPv6 subnets (/126 minimum for 4 addresses)
	MaxMaskIPv6 = 126
	// This assumes all the ip start with 1 for now before we address
	// the issue: https://github.com/aws/amazon-ecs-cni-plugins/issues/37
	IPPrefix = "1"
	// IPPrefixV6 is the prefix for IPv6 addresses in the database
	IPPrefixV6 = "6"
	// LastKnownIPv6Key is the key used to store the last allocated IPv6 address in the database
	LastKnownIPv6Key = "lastKnownIPv6"
)

// IPManager is responsible for managing the ip addresses using boltdb
type IPManager struct {
	client        store.Store
	subnet        net.IPNet  // IPv4 subnet (kept for backward compatibility)
	subnetV4      *net.IPNet // nil if IPv4 not configured
	subnetV6      *net.IPNet // nil if IPv6 not configured
	lastKnownIP   net.IP     // IPv4 last known IP (kept for backward compatibility)
	lastKnownIPv4 net.IP
	lastKnownIPv6 net.IP
}

// Config represents the configuration for boltdb opermation where the
// ip address are stored
type Config struct {
	DB                string
	PersistConnection bool
	Bucket            string
	ConnectionTimeout time.Duration
}

// IPAllocator defines the operation for an ip allocator
type IPAllocator interface {
	GetAvailableIP(string) (string, error)
	GetAvailableIPv6(string) (string, error)
	Get(string) (string, error)
	Assign(string, string) error
	Update(string, string) error
	Release(string) error
	ReleaseByID(string) (ipv4Released, ipv6Released string, err error)
	Exists(string) (bool, error)
	SetLastKnownIP(net.IP)
	SetLastKnownIPv6(net.IP)
	Close()
}

// NewIPAllocator creates an ip manager from the IPAM and  db configuration
func NewIPAllocator(options *Config, subnet net.IPNet) (IPAllocator, error) {
	config := &store.Config{
		PersistConnection: options.PersistConnection,
		ConnectionTimeout: options.ConnectionTimeout,
		Bucket:            options.Bucket,
	}
	client, err := boltdb.New([]string{options.DB}, config)
	if err != nil {
		return nil, err
	}

	lastKnownIP := subnet.IP.Mask(subnet.Mask)
	return &IPManager{
		client:        client,
		subnet:        subnet,
		subnetV4:      &subnet,
		subnetV6:      nil,
		lastKnownIP:   lastKnownIP,
		lastKnownIPv4: lastKnownIP,
		lastKnownIPv6: nil,
	}, nil
}

// NewIPAllocatorDualStack creates an IP manager supporting both IPv4 and IPv6
// subnetV4 and subnetV6 can be nil if that stack is not configured
func NewIPAllocatorDualStack(options *Config, subnetV4, subnetV6 *net.IPNet) (IPAllocator, error) {
	config := &store.Config{
		PersistConnection: options.PersistConnection,
		ConnectionTimeout: options.ConnectionTimeout,
		Bucket:            options.Bucket,
	}
	client, err := boltdb.New([]string{options.DB}, config)
	if err != nil {
		return nil, err
	}

	var lastKnownIPv4 net.IP
	var lastKnownIPv6 net.IP
	var subnet net.IPNet

	if subnetV4 != nil {
		lastKnownIPv4 = subnetV4.IP.Mask(subnetV4.Mask)
		subnet = *subnetV4
	}

	if subnetV6 != nil {
		lastKnownIPv6 = subnetV6.IP.Mask(subnetV6.Mask)
		// Ensure it's 16 bytes for IPv6
		if len(lastKnownIPv6) != 16 {
			lastKnownIPv6 = lastKnownIPv6.To16()
		}
	}

	return &IPManager{
		client:        client,
		subnet:        subnet,
		subnetV4:      subnetV4,
		subnetV6:      subnetV6,
		lastKnownIP:   lastKnownIPv4,
		lastKnownIPv4: lastKnownIPv4,
		lastKnownIPv6: lastKnownIPv6,
	}, nil
}

// SetLastKnownIP updates the record of last visited ip address
func (manager *IPManager) SetLastKnownIP(ip net.IP) {
	manager.lastKnownIP = ip
}

// SetLastKnownIPv6 updates the record of last visited IPv6 address
func (manager *IPManager) SetLastKnownIPv6(ip net.IP) {
	// Ensure we store the full 16-byte representation
	if ip != nil && len(ip) != 16 {
		ip = ip.To16()
	}
	manager.lastKnownIPv6 = ip
}

// GetAvailableIP returns the next available ip address
func (manager *IPManager) GetAvailableIP(id string) (string, error) {
	var err error
	nextIP := manager.lastKnownIP
	for {
		nextIP, err = NextIP(nextIP, manager.subnet)
		if err != nil {
			return "", err
		}
		err = manager.Assign(nextIP.String(), id)
		if err != nil && err != store.ErrKeyExists {
			return "", errors.Wrapf(err, "ipstore get ip: failed to assign ip in ipam")
		} else if err == store.ErrKeyExists {
			// ip already be used
		} else {
			// assing the ip succeed
			manager.lastKnownIP = nextIP
			return nextIP.String(), nil
		}
		if nextIP.Equal(manager.lastKnownIP) {
			return "", errors.New("getAvailableIP ipstore: failed to find available ip addresses in the subnet")
		}
	}
}

// GetAvailableIPv6 returns the next available IPv6 address from the configured subnet
func (manager *IPManager) GetAvailableIPv6(id string) (string, error) {
	if manager.subnetV6 == nil {
		return "", errors.New("getAvailableIPv6 ipstore: IPv6 subnet not configured")
	}

	var err error
	startIP := manager.lastKnownIPv6
	if startIP == nil {
		// Initialize to network address if not set
		startIP = manager.subnetV6.IP.Mask(manager.subnetV6.Mask)
		if len(startIP) != 16 {
			startIP = startIP.To16()
		}
	}

	nextIP := startIP
	for {
		nextIP, err = NextIPv6(nextIP, *manager.subnetV6)
		if err != nil {
			return "", err
		}

		// Store IPv6 addresses with the "6" prefix to distinguish from IPv4
		ipKey := IPPrefixV6 + nextIP.String()
		err = manager.assignIPv6(ipKey, id)
		if err != nil && err != store.ErrKeyExists {
			return "", errors.Wrapf(err, "ipstore get ipv6: failed to assign ip in ipam")
		} else if err == store.ErrKeyExists {
			// ip already in use, continue searching
		} else {
			// assign succeeded
			manager.lastKnownIPv6 = nextIP
			return nextIP.String(), nil
		}

		if nextIP.Equal(startIP) {
			return "", errors.New("getAvailableIPv6 ipstore: failed to find available IPv6 addresses in the subnet")
		}
	}
}

// assignIPv6 marks an IPv6 address as used or returns an error if already in use
func (manager *IPManager) assignIPv6(ipKey string, id string) error {
	ok, err := manager.client.Exists(ipKey)
	if err != nil && err != store.ErrKeyNotFound {
		return errors.Wrapf(err, "assign ipstore: query the db failed, err: %v", err)
	}
	if ok {
		return store.ErrKeyExists
	}

	// if the id presents, check uniqueness within IPv6 addresses only
	// (same ID can be used for IPv4 and IPv6 in dual-stack mode)
	if id != "" {
		ok, err := manager.UniqueIDv6(id)
		if err != nil {
			return errors.Wrapf(err, "assign ipstore: check id unique failed, id: %s", id)
		}
		if !ok {
			return errors.Errorf("assign ipstore: id already exists in IPv6, id: %s", id)
		}
	}

	err = manager.client.Put(ipKey, []byte(id), nil)
	if err != nil {
		return errors.Wrapf(err, "assign ipstore: failed to put the key/value into the db: %s -> %s", ipKey, id)
	}

	return nil
}

// UniqueIDv6 checks whether the id has already existed in the IPv6 addresses only
func (manager *IPManager) UniqueIDv6(id string) (bool, error) {
	// Check IPv6 addresses only
	kvPairsV6, err := manager.client.List(IPPrefixV6)
	if err != nil && err != store.ErrKeyNotFound {
		return false, errors.Wrapf(err, "ipstore: failed to list IPv6 key-value pairs in db")
	}
	if err != store.ErrKeyNotFound {
		for _, kvPair := range kvPairsV6 {
			if string(kvPair.Value) == id {
				return false, errors.Errorf("ipstore: id already exists in IPv6")
			}
		}
	}

	return true, nil
}

// UniqueIDDualStack checks whether the id has already existed in the ipam for both IPv4 and IPv6
func (manager *IPManager) UniqueIDDualStack(id string) (bool, error) {
	// Check IPv4 addresses
	kvPairsV4, err := manager.client.List(IPPrefix)
	if err != nil && err != store.ErrKeyNotFound {
		return false, errors.Wrapf(err, "ipstore: failed to list IPv4 key-value pairs in db")
	}
	if err != store.ErrKeyNotFound {
		for _, kvPair := range kvPairsV4 {
			if string(kvPair.Value) == id {
				return false, errors.Errorf("ipstore: id already exists")
			}
		}
	}

	// Check IPv6 addresses
	kvPairsV6, err := manager.client.List(IPPrefixV6)
	if err != nil && err != store.ErrKeyNotFound {
		return false, errors.Wrapf(err, "ipstore: failed to list IPv6 key-value pairs in db")
	}
	if err != store.ErrKeyNotFound {
		for _, kvPair := range kvPairsV6 {
			if string(kvPair.Value) == id {
				return false, errors.Errorf("ipstore: id already exists")
			}
		}
	}

	return true, nil
}

// Get returns the id by which the ip was used and return empty if the key not exists
func (manager *IPManager) Get(ip string) (string, error) {
	kvPair, err := manager.client.Get(ip)
	if err != nil && err != store.ErrKeyNotFound {
		return "", errors.Wrapf(err, "get ipstore: failed to get %v from db", kvPair)
	}
	if err == store.ErrKeyNotFound {
		return "", nil
	}

	return string(kvPair.Value), nil
}

// Assign marks the ip as used or return an error if the ip has already been used
func (manager *IPManager) Assign(ip string, id string) error {
	ok, err := manager.Exists(ip)
	if err != nil {
		return errors.Wrapf(err, "assign ipstore: query the db failed, err: %v", err)
	}
	if ok {
		return store.ErrKeyExists
	}

	// if the id presents, it should be unique
	if id != "" {
		ok, err := manager.UniqueID(id)
		if err != nil {
			return errors.Wrapf(err, "assign ipstore: check id unique failed, id: %s", id)
		}
		if !ok {
			return errors.Errorf("assign ipstore: id already exists, id: %s", id)
		}
	}

	err = manager.client.Put(ip, []byte(id), nil)
	if err != nil {
		return errors.Wrapf(err, "assign ipstore: failed to put the key/value into the db: %s -> %s", ip, id)
	}

	manager.lastKnownIP = net.ParseIP(ip)
	return nil
}

// Release marks the ip as available or return an error if
// the ip is avaialble already
func (manager *IPManager) Release(ip string) error {
	ok, err := manager.Exists(ip)
	if err != nil {
		return errors.Wrap(err, "release ipstore: failed to query the db")
	}
	if !ok {
		return errors.Errorf("release ipstore: ip does not existed in the db: %s", ip)
	}

	err = manager.client.Delete(ip)
	if err != nil {
		return errors.Wrap(err, "release ipstore: failed to delete the key in the db")
	}

	manager.lastKnownIP = net.ParseIP(ip)

	return nil
}

// ReleaseByID releases all IPs (v4 and v6) associated with an ID
// It searches both IPv4 and IPv6 prefixes in the database and returns both released IPs
func (manager *IPManager) ReleaseByID(id string) (ipv4Released, ipv6Released string, err error) {
	// Search IPv4 addresses (prefix "1")
	kvPairsV4, errV4 := manager.client.List(IPPrefix)
	if errV4 != nil && errV4 != store.ErrKeyNotFound {
		return "", "", errors.Wrapf(errV4, "release ipstore: failed to list IPv4 key-value pairs in db")
	}

	// Search for IPv4 address with matching ID
	if errV4 != store.ErrKeyNotFound {
		for _, kvPair := range kvPairsV4 {
			if string(kvPair.Value) == id {
				err = manager.Release(kvPair.Key)
				if err != nil {
					return "", "", err
				}
				ipv4Released = kvPair.Key
				break
			}
		}
	}

	// Search IPv6 addresses (prefix "6")
	kvPairsV6, errV6 := manager.client.List(IPPrefixV6)
	if errV6 != nil && errV6 != store.ErrKeyNotFound {
		return ipv4Released, "", errors.Wrapf(errV6, "release ipstore: failed to list IPv6 key-value pairs in db")
	}

	// Search for IPv6 address with matching ID
	if errV6 != store.ErrKeyNotFound {
		for _, kvPair := range kvPairsV6 {
			if string(kvPair.Value) == id {
				// Release the IPv6 address (stored with "6" prefix)
				err = manager.releaseIPv6(kvPair.Key)
				if err != nil {
					return ipv4Released, "", err
				}
				// Return the IP without the "6" prefix
				ipv6Released = kvPair.Key[len(IPPrefixV6):]
				break
			}
		}
	}

	// If neither IPv4 nor IPv6 was found, return an error
	if ipv4Released == "" && ipv6Released == "" {
		return "", "", errors.Errorf("release ipstore: no ip address associated with the given id: %s", id)
	}

	return ipv4Released, ipv6Released, nil
}

// releaseIPv6 marks an IPv6 address as available or returns an error if
// the address is not in the database. The ipKey should include the "6" prefix.
func (manager *IPManager) releaseIPv6(ipKey string) error {
	ok, err := manager.client.Exists(ipKey)
	if err != nil && err != store.ErrKeyNotFound {
		return errors.Wrap(err, "release ipstore: failed to query the db for IPv6")
	}
	if !ok {
		return errors.Errorf("release ipstore: IPv6 ip does not exist in the db: %s", ipKey)
	}

	err = manager.client.Delete(ipKey)
	if err != nil {
		return errors.Wrap(err, "release ipstore: failed to delete the IPv6 key in the db")
	}

	// Update lastKnownIPv6 (strip the "6" prefix to get the actual IP)
	if len(ipKey) > len(IPPrefixV6) {
		ipStr := ipKey[len(IPPrefixV6):]
		manager.lastKnownIPv6 = net.ParseIP(ipStr)
	}

	return nil
}

// UniqueID checks whether the id has already existed in the ipam
func (manager *IPManager) UniqueID(id string) (bool, error) {
	kvPairs, err := manager.client.List(IPPrefix)
	// TODO improve this part by implement listing all the kv pairs
	if err == store.ErrKeyNotFound {
		return true, nil
	}

	if err != nil {
		return false, errors.Wrapf(err, "ipstore: failed to list the key-value pairs in db")
	}

	for _, kvPair := range kvPairs {
		if string(kvPair.Value) == id {
			return false, errors.Errorf("ipstore: id already exists")
		}
	}
	return true, nil
}

// Update updates the value of existed key in the db
func (manager *IPManager) Update(key string, value string) error {
	return manager.client.Put(key, []byte(value), nil)
}

// Exists checks whether the ip is used or not
func (manager *IPManager) Exists(ip string) (bool, error) {
	ok, err := manager.client.Exists(ip)
	if err == store.ErrKeyNotFound {
		return false, nil
	}

	return ok, err
}

// Close will close the connection to the db
func (manager *IPManager) Close() {
	manager.client.Close()
}

// NextIPv6 returns the next IP in an IPv6 subnet
// It handles 128-bit arithmetic using math/big and skips the network address
// (IPv6 has no broadcast address to skip)
func NextIPv6(ip net.IP, subnet net.IPNet) (net.IP, error) {
	// Validate prefix length
	ones, _ := subnet.Mask.Size()
	if ones > MaxMaskIPv6 {
		return nil, errors.Errorf("nextIPv6 ipstore: no available ip in subnet: %v", subnet)
	}

	// Ensure we have a valid IPv6 address (not IPv4)
	ipv6 := ip.To16()
	if ipv6 == nil || ipv6.To4() != nil {
		return nil, errors.Errorf("nextIPv6 ipstore: invalid ipv6 address: %v", ip)
	}

	// Verify IP is in subnet
	if !subnet.Contains(ipv6) {
		return nil, errors.Errorf("nextIPv6 ipstore: ip %v not in subnet %s", ipv6, subnet.String())
	}

	// Calculate min (network) address
	minIP := subnet.IP.Mask(subnet.Mask)
	// Ensure minIP is 16 bytes
	if len(minIP) != 16 {
		minIP = minIP.To16()
	}

	// Calculate max address (all host bits set to 1)
	maxIP := make(net.IP, 16)
	for i := 0; i < 16; i++ {
		maxIP[i] = minIP[i] | ^subnet.Mask[i]
	}

	nextIP := ipv6
	// Skip network address only (IPv6 has no broadcast)
	for nextIP.Equal(ipv6) || nextIP.Equal(minIP) {
		if nextIP.Equal(maxIP) {
			nextIP = minIP
		}
		// Increment IP using big.Int for 128-bit arithmetic
		nextIPInt := big.NewInt(0).SetBytes(nextIP)
		nextIPInt.Add(nextIPInt, big.NewInt(1))

		// Ensure result is 16 bytes (pad with leading zeros if needed)
		nextIPBytes := nextIPInt.Bytes()
		if len(nextIPBytes) < 16 {
			nextIP = make(net.IP, 16)
			copy(nextIP[16-len(nextIPBytes):], nextIPBytes)
		} else {
			nextIP = nextIPBytes
		}
	}

	return nextIP, nil
}

// NextIP returns the next ip in the subnet
func NextIP(ip net.IP, subnet net.IPNet) (net.IP, error) {
	if ones, _ := subnet.Mask.Size(); ones > MaxMask {
		return nil, errors.Errorf("nextIP ipstore: no available ip in the subnet: %v", subnet)
	}

	// currently only ipv4 is supported
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, errors.Errorf("nextIP ipstore: invalid ipv4 address: %v", ipv4)
	}

	if !subnet.Contains(ipv4) {
		return nil, errors.Errorf("nextIP ipstore: ip %v is not within subnet %s", ipv4.String(), subnet.String())
	}

	minIP := subnet.IP.Mask(subnet.Mask)
	maxIP := net.IP(make([]byte, 4))
	for i := range ipv4 {
		maxIP[i] = minIP[i] | ^subnet.Mask[i]
	}

	nextIP := ipv4
	// Reserve the broadcast address(all 1) and the network address(all 0)
	for nextIP.Equal(ipv4) || nextIP.Equal(minIP) || nextIP.Equal(maxIP) {
		if nextIP.Equal(maxIP) {
			nextIP = minIP
		}
		// convert the IP into Int for easily calculation
		nextIPInBytes := big.NewInt(0).SetBytes(nextIP)
		nextIPInBytes.Add(nextIPInBytes, big.NewInt(1))
		nextIP = net.IP(nextIPInBytes.Bytes())
	}

	return nextIP, nil
}
