# Amazon ECS CNI Plugins

[![Build Status](https://travis-ci.org/aws/amazon-ecs-cni-plugins.svg?branch=master)](https://travis-ci.org/aws/amazon-ecs-cni-plugins)
## Description

Amazon ECS CNI Plugins is a collection of Container Network Interface([CNI](https://github.com/containernetworking/cni)) Plugins used by the [Amazon ECS Agent](https://github.com/aws/amazon-ecs-agent) to configure network namespace of containers with Elastic Network Interfaces ([ENIs](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html))

For more information about Amazon ECS, see the [Amazon ECS Developer Guide](http://docs.aws.amazon.com/AmazonECS/latest/developerguide/Welcome.html).

For more information about Plugins in this project, see the individual READMEs.

## Plugins
* [ECS ENI Plugin](plugins/eni/README.md): configures the network namespace of the container with an ENI device
* [ECS Bridge Plugin](plugins/ecs-bridge/README.md): configures the network namespace of the container to be able to communicate with the credentials endpoint of the ECS Agent
* [ECS IPAM Plugin](plugins/ipam/README.md): allocates an IP address and constructs Gateway and Route structures used by the ECS Bridge plugin to configure the bridge and veth pair in the container network namespace

## Security disclosures
If you think you’ve found a potential security issue, please do not post it in the Issues.  Instead, please follow the instructions [here](https://aws.amazon.com/security/vulnerability-reporting/) or [email AWS security directly](mailto:aws-security@amazon.com).
