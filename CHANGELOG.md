## 2024.09.0
* Enhancement - Migrate to Go modules. [#113](https://github.com/aws/amazon-ecs-cni-plugins/pull/113)

## 2020.09.0
* Feature - Support multiple IP (v4 and v6) addresses per interface. [#98](https://github.com/aws/amazon-ecs-cni-plugins/pull/98)

## 2019.10.0
* Enhancement - Add `MTU` field into ENI config. [#95](https://github.com/aws/amazon-ecs-cni-plugins/pull/95)
* Enhancement - Add `stay-down` config to ENI plugin. [#94](https://github.com/aws/amazon-ecs-cni-plugins/pull/94)

## 2019.06.0
* Bug - Fixed race condition in ecs-bridge plugin. [#90](https://github.com/aws/amazon-ecs-cni-plugins/pull/90)

## 2018.10.0
* Enhancement - Remove dependency on DHCP client. [#83](https://github.com/aws/amazon-ecs-cni-plugins/pull/83)

## 2018.08.0
* Enhancement - Reduced the ENI plugin execution time by removing the 
  dependency on instance metadata service (by adding the `subnetgateway-ipv4-address`
  config flag). [#81](https://github.com/aws/amazon-ecs-cni-plugins/pull/81)
 
## 2018.02.0
* Bug - Fixed an issue where container wasn't able to talk to agent endpoint.
[#73](https://github.com/aws/amazon-ecs-cni-plugins/pull/73)
* Enhancement - Use the `CNI_IFNAME` in `ecs-eni` plugin as the ENI interface
name. [#59](https://github.com/aws/amazon-ecs-cni-plugins/pull/59)

## 2018.01.1
* Enhancement - Increase the timeout to 1 minute for `ecs-eni` to retrieve MAC
  address of eni from instance metadata. [#69](https://github.com/aws/amazon-ecs-cni-plugins/pull/69)

## 2018.01.0
* Enhancement - Increase the timeout for `ecs-eni` to retrieve MAC address of
  eni from instance metadata. [#66](https://github.com/aws/amazon-ecs-cni-plugins/pull/66)

## 2017.10.1
* Bug - Add retry in `ecs-eni` for retrieving MAC address of eni from ec2
  instance metadata. [#62](https://github.com/aws/amazon-ecs-cni-plugins/pull/62)

## 2017.10.0
* Feature - Implement `ecs-eni`, `ecs-bridge` and `ecs-ipam` plugins to
  provision ENIs for containers.
