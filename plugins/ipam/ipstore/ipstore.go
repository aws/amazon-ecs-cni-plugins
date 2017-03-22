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
	"math"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/aws/amazon-ecs-cni-plugins/plugins/ipam/config"
	log "github.com/cihub/seelog"
	"github.com/docker/libkv/store"
	"github.com/docker/libkv/store/boltdb"
	"github.com/pkg/errors"
)

// IPManager is responsible for managing the ip addresses using boltdb
type IPManager struct {
	client      store.Store
	subnet      net.IPNet
	lastKnownIP net.IP
	allocated   int
	updateLock  sync.RWMutex
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
	Get(string) (string, error)
	Assign(string, string) error
	Update(string, string) error
	Release(string) error
	Exists(string) (bool, error)
	SetLastKnownIP(net.IP)
	Close()
}

// New creates an ip manager from the db configuration
func New(options *Config, subnet net.IPNet) (IPAllocator, error) {
	config := &store.Config{
		PersistConnection: options.PersistConnection,
		ConnectionTimeout: options.ConnectionTimeout,
		Bucket:            options.Bucket,
	}
	client, err := boltdb.New([]string{options.DB}, config)
	if err != nil {
		return nil, err
	}

	return &IPManager{
		client:      client,
		subnet:      subnet,
		allocated:   0,
		lastKnownIP: subnet.IP.Mask(subnet.Mask),
	}, nil
}

// NewFromIPAM creates the ip addresses manager from the IPAM configuration
func NewFromIPAM(conf *config.IPAMConfig) (IPAllocator, error) {
	timeout := config.DefaultConnectionTimeout
	if conf.Timeout != "" {
		duration, err := time.ParseDuration(conf.Timeout)
		if err != nil {
			return nil, errors.Errorf("NewIPManagerFromConf main: parsing duration from string failed: %v", err)
		}
		timeout = duration
	}

	dbConf := &Config{
		PersistConnection: false,
		Bucket:            conf.Bucket,
		ConnectionTimeout: timeout,
		DB:                conf.DB,
	}

	return New(dbConf, net.IPNet{
		IP:   conf.IPV4Subnet.IP,
		Mask: conf.IPV4Subnet.Mask,
	})
}

// SetLastKnownIP updates the record of last visited ip address
func (manager *IPManager) SetLastKnownIP(ip net.IP) {
	manager.updateLock.Lock()
	defer manager.updateLock.Unlock()

	manager.lastKnownIP = ip
}

// GetAvailableIP returns the next available ip address
func (manager *IPManager) GetAvailableIP(id string) (string, error) {
	manager.updateLock.RLock()
	defer manager.updateLock.RUnlock()

	// NO. of IP address in the subnet
	ones, bits := manager.subnet.Mask.Size()
	total := int(math.Pow(2, float64(bits-ones)) - 1)

	if manager.allocated >= total {
		return "", errors.New("GetAvailableIP ipstore: all the ip addresses are used in the subnet")
	}

	startIP := manager.lastKnownIP
	for i := 0; i < total; i++ {
		ip, err := NextIP(startIP, manager.subnet)
		if err != nil {
			return "", err
		}
		startIP = ip

		ok, err := manager.exists(ip.String())
		if err != nil {
			log.Debugf("query to the db failed, err: %v", err)
			return "", err
		}

		if !ok {
			manager.lastKnownIP = ip

			err = manager.assign(ip.String(), id)
			if err != nil {
				return "", err
			}
			return ip.String(), nil
		}
	}

	return "", errors.New("GetAvailableIP ipstore: failed to find available ip addresses in the subnet")
}

// Get returns the id by which the ip was used
func (manager *IPManager) Get(ip string) (string, error) {
	manager.updateLock.RLock()
	defer manager.updateLock.RUnlock()

	kvPair, err := manager.client.Get(ip)
	if err != nil {
		return "", err
	}

	return string(kvPair.Value), nil
}

// Assign marks the ip as used or return an error if the
// ip has already been used
func (manager *IPManager) Assign(ip string, id string) error {
	manager.updateLock.Lock()
	defer manager.updateLock.Unlock()

	ok, err := manager.exists(ip)
	if err != nil {
		return errors.Wrapf(err, "Assign ipstore: query the db failed, err: %v", err)
	}
	if ok {
		return errors.Errorf("Assign ipstore: ip %v already been used", ip)
	}
	return manager.assign(ip, id)
}

// assign will insert a record into the db to indicate the ip has already
// been used, it should be used with a lock to avoild race condtition
func (manager *IPManager) assign(ip string, id string) error {
	err := manager.client.Put(ip, []byte(id), nil)
	if err != nil {
		return errors.Wrapf(err, "assign ipstore: failed to put the key/value into the db: %s -> %s", ip, id)
	}

	manager.lastKnownIP = net.ParseIP(ip)
	manager.allocated++

	return nil
}

// Release marks the ip as available or return an error if
// the ip is avaialble already
func (manager *IPManager) Release(ip string) error {
	manager.updateLock.Lock()
	defer manager.updateLock.Unlock()

	ok, err := manager.exists(ip)

	if err != nil {
		return errors.Wrap(err, "Release ipstore: failed to query the db")
	}
	if !ok {
		return errors.Errorf("Release ipstore: ip does not existed in the db: %s", ip)
	}

	err = manager.client.Delete(ip)
	if err != nil {
		return errors.Wrap(err, "Release ipstore: failed to delete the key in the db")
	}

	manager.allocated--
	manager.lastKnownIP = net.ParseIP(ip)

	return nil
}

// Update updates the value of existed key in the db
func (manager *IPManager) Update(key string, value string) error {
	manager.updateLock.Lock()
	defer manager.updateLock.Unlock()

	return manager.client.Put(key, []byte(value), nil)
}

// Exists checks whether the ip is used or not
func (manager *IPManager) Exists(ip string) (bool, error) {
	manager.updateLock.RLock()
	defer manager.updateLock.RUnlock()

	return manager.exists(ip)
}

func (manager *IPManager) exists(ip string) (bool, error) {
	exist, err := manager.client.Exists(ip)
	if err == store.ErrKeyNotFound {
		return false, nil
	}

	return exist, err
}

// Close will close the connection to the db
func (manager *IPManager) Close() {
	manager.client.Close()
}

// NextIP returns the next ip in the subnet
func NextIP(ip net.IP, subnet net.IPNet) (net.IP, error) {
	if ones, _ := subnet.Mask.Size(); ones > 30 {
		return nil, errors.Errorf("NextIP ipstore: no available ip in the subnet: %v", subnet)
	}

	// currently only ipv4 is supported
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, errors.Errorf("NextIP ipstore: invalid ipv4 address: %v", ipv4)
	}

	if !subnet.Contains(ipv4) {
		return nil, errors.Errorf("NextIP ipstore: ip %v is not within subnet %s", ipv4.String(), subnet.String())
	}

	minIP := subnet.IP.Mask(subnet.Mask)
	maxIP := net.IP(make([]byte, 4))
	for i := range ipv4 {
		maxIP[i] = minIP[i] | ^subnet.Mask[i]
	}

	nextIP := ipv4
	for nextIP.Equal(ipv4) || nextIP.Equal(minIP) || nextIP.Equal(maxIP) {
		if nextIP.Equal(maxIP) {
			nextIP = minIP
		}
		i := big.NewInt(0).SetBytes(nextIP)
		i.Add(i, big.NewInt(1))
		nextIP = net.IP(i.Bytes())
	}

	return nextIP, nil
}
