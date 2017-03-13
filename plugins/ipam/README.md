# ipam plugin

## Overview

Ipam plugin will construct the IP, Gateway, Routes as a struct which will be used by the bridge plugin to configure the bridge and veth pair in container network namespace. Example of this configuration looks like:
```
{
		"ipam": {
			"type": "ecs-ipam",
			"db": "/var/lib/ecs",
			"bucket": "ecs_ips",
			"timeout": "5s",
			"ipAddress": "10.0.0.2/24",
			"gateway": "10.0.0.1",
			"subnet": "10.0.0.0/24",
			"routes": [
				{"dst": "169.254.170.2/32"},
				{"dst": "169.254.170.0/20", "gw": "10.0.0.1"}
			]
		}
}
```
## Parameter
* `ipAddress` (string, required): ipv4 address of the veth inside the container network namespace.
* `routes` (string, optional): list of routes to add to the container network namespace. Each route is a dictionary with "dst" and optional "gw" fields. If "gw" is omitted, value of "gateway" will be used.
* `gateway` (string, optional): IP inside of "subnet" to designate as the gateway. Defaults to ".1" IP inside of the "subnet" block.
* `subnet` (string, required): CIDR block to allocate out of.
* `timeout` (string, optional): timeout for the connection to the boltdb.
* `db` (string, required): where the boltdb file should put.
* `bucket` (string, required): bucket name of the boltdb.
