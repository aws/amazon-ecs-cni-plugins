## 2018.01.0
* Enhancement - Increase the timeout for `ecs-eni` to retrieve MAC address of
  eni from instance metadata. [#66](https://github.com/aws/amazon-ecs-cni-plugins/pull/66)

## 2017.10.1
* Bug - Add retry in `ecs-eni` for retrieving MAC address of eni from ec2
  instance metadata. [#62](https://github.com/aws/amazon-ecs-cni-plugins/pull/62)

## 2017.10.0
* Feature - Implement `ecs-eni`, `ecs-bridge` and `ecs-ipam` plugins to
  provision ENIs for containers.
