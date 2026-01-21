# ECS IPAM plugin

## Overview

The ECS IPAM plugin constructs the IP, Gateway and Routes, which are used 
by the ECS Bridge plugin to configure the bridge and veth pair in the 
container network namespace. The plugin supports IPv4-only, IPv6-only, or 
dual-stack (both IPv4 and IPv6) configurations.

### IPv4-Only Configuration Example
```json
{
    "ipam": {
        "type": "ecs-ipam",
        "id": "12345",
        "ipv4-address": "10.0.0.2/24",
        "ipv4-gateway": "10.0.0.1",
        "ipv4-subnet": "10.0.0.0/24",
        "ipv4-routes": [
            {"dst": "169.254.170.2/32"},
            {"dst": "169.254.170.0/20", "gw": "10.0.0.1"}
        ]
    }
}
```

### Dual-Stack Configuration Example
```json
{
    "ipam": {
        "type": "ecs-ipam",
        "id": "container-12345",
        "ipv4-subnet": "10.0.0.0/24",
        "ipv4-address": "10.0.0.2/24",
        "ipv4-gateway": "10.0.0.1",
        "ipv4-routes": [
            {"dst": "169.254.170.2/32"}
        ],
        "ipv6-subnet": "2001:db8::/64",
        "ipv6-address": "2001:db8::2/64",
        "ipv6-gateway": "2001:db8::1",
        "ipv6-routes": [
            {"dst": "fd00:ec2::254/128"}
        ]
    }
}
```

### IPv6-Only Configuration Example
```json
{
    "ipam": {
        "type": "ecs-ipam",
        "id": "container-12345",
        "ipv6-subnet": "2001:db8::/64",
        "ipv6-gateway": "2001:db8::1"
    }
}
```

## Parameters

### General Parameters
* `id` (string, optional): information about this ip, can be any information related
to this ip.

*Note: either `id` or an IP address (`ipv4-address` or `ipv6-address`) must be specified in delete operation.*

### IPv4 Configuration Parameters
* `ipv4-subnet` (string, required for IPv4): CIDR block for IPv4 address allocations.
* `ipv4-address` (string, optional): IPv4 address of the veth inside the
container network namespace. If not specified, an address will be automatically
allocated from the subnet.
* `ipv4-gateway` (string, optional): IP inside of "subnet" to designate as the
gateway. Defaults to the first usable address (`.1`) inside of the "subnet" block.
* `ipv4-routes` (string, optional): list of routes to add to the container network
namespace. Each route is a dictionary with "dst" and optional "gw" fields. 
If "gw" is omitted, value of "gateway" will be used.

### IPv6 Configuration Parameters
* `ipv6-subnet` (string, required for IPv6): CIDR block for IPv6 address allocations.
Supports standard IPv6 prefix lengths including /64 (typical LAN), /48, /56, and /128.
* `ipv6-address` (string, optional): IPv6 address with prefix length (e.g., `2001:db8::2/64`)
of the veth inside the container network namespace. If not specified, an address will be
automatically allocated from the subnet.
* `ipv6-gateway` (string, optional): IPv6 address inside of "subnet" to designate as the
gateway. Defaults to the first usable address in the subnet (network address + 1).
* `ipv6-routes` (string, optional): list of IPv6 routes to add to the container network
namespace. Each route is a dictionary with "dst" and optional "gw" fields.
If "gw" is omitted, value of "ipv6-gateway" will be used.

### Configuration Notes
* At least one subnet (`ipv4-subnet` or `ipv6-subnet`) must be specified.
* When both `ipv4-subnet` and `ipv6-subnet` are configured, the plugin operates in
dual-stack mode and allocates both IPv4 and IPv6 addresses.
* IPv6 addresses are validated as 128-bit addresses with valid prefix lengths (0-128).
* IPv6 does not use broadcast addresses, so the full address range (except the network
address) is available for allocation.
* When `ipv6-gateway` is not specified but `ipv6-subnet` is provided, the default
gateway is calculated as the first usable address in the subnet.

## Environment Variables
* `IPAM_DB_PATH` (string, optional): path of the boltdb file.
* `IPAM_DB_CONNECTION_TIMEOUT` (string, optional): timeout for the connection
to the boltdb.

## Example
Before running the command you should set up these environment variable:
* `CNI_COMMAND`: Command to execute eg: ADD.
* `CNI_PATH`: Plugin binary path eg: `pwd`/bin.
* `CNI_IFNAME`: Interface name inside the container, this is only required for
bridge plugin, but is hard coded in skel package which we consume. So for using
the ipam plugin separately, it should be set but won't be used.
Ref: https://github.com/containernetworking/cni/blob/v0.5.1/pkg/skel/skel.go#L53
### Add:
```
export CNI_COMMAND=ADD && cat mynet.conf | ../bin/ecs-ipam
```

### Del:
```
export CNI_COMMAND=DEL && cat mynet.conf | ../bin/ecs-ipam
```

`mynet.conf` is the configuration file for the plugin, it's the same as described
in the overview above.

Then you can use the following program to check the content of the db, be sure
to change the boltdb path and bucket name:
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
    db := "${BOLTDB_PATH}"
    bucket := "${BUCKET_NAME}"

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
