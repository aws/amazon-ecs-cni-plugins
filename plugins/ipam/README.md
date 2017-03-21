# IPAM plugin

## Overview

IPAM plugin will construct the IP, Gateway, Routes as a struct which will be used by the bridge plugin to configure the bridge and veth pair in container network namespace. Example of this configuration looks like:
```
{
		"ipam": {
			"type": "ecs-ipam",
			"ipv4-address": "10.0.0.2/24",
			"ipv4-gateway": "10.0.0.1",
			"ipv4-subnet": "10.0.0.0/24",
			"routes": [
				{"dst": "169.254.170.2/32"},
				{"dst": "169.254.170.0/20", "gw": "10.0.0.1"}
			]
		}
}
```
## Parameter
* `ipv4-address` (string, optional): ipv4 address of the veth inside the container network namespace.
* `routes` (string, optional): list of routes to add to the container network namespace. Each route is a dictionary with "dst" and optional "gw" fields. If "gw" is omitted, value of "gateway" will be used.
* `ipv4-gateway` (string, optional): IP inside of "subnet" to designate as the gateway. Defaults to ".1" IP inside of the "subnet" block.
* `ipv4-subnet` (string, required): CIDR block to allocate out of.

## Environment variable
* `IPAM_DB_NAME` (string, required): path of the boltdb file.
* `IPAM_BUCKET_NAME` (string, required): bucket name of the boltdb.
* `IPAM_TIMEOUT` (string, optional): timeout for the connection to the boltdb.

## Example
Before running the command you should set up the environment variable `CNI_CONTAINERID`, `CNI_NETNS`, `CNI_PATH` and `CNI_IFNAME` to any value, which is required for other plugin.
### Add:
```
export CNI_COMMAND=ADD && cat /etc/cni/net.d/mynet.conf | ../bin/ipam
```

### Del:
```
export CNI_COMMAND=DEL && cat /etc/cni/net.d/mynet.conf | ../bin/ipam
```

Then you can use the following program to check the content of the db:
```golang
package main

import (
	"fmt"
	"github.com/docker/libkv"
	"github.com/docker/libkv/store"
	"github.com/libkv/store/boltdb"
	"time"
)

func init() {
	boltdb.Register()
}

func main() {
	db := "/home/ec2-user/db"
	bucket := "bucket"

	kv, err := libkv.NewStore(
		store.BOLTDB,
		[]string{db},
		&store.Config{
			Bucket:            bucket,
			ConnectionTimeout: 10 * time.Second,
		},
	)
	if err != nil {
		fmt.Printf("Creating db failed: %v\n", err)
	}

	entries, err := kv.List("1")
	for _, pair := range entries {
		fmt.Printf("key=%v - value=%v\n", pair.Key, string(pair.Value))
	}
}
```
