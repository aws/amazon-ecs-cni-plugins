module github.com/aws/amazon-ecs-cni-plugins

go 1.22.0

require (
	github.com/aws/aws-sdk-go v1.5.11-0.20161122232317-92ed7a76d078
	github.com/cihub/seelog v0.0.0-20161009225354-175e6e3d439f
	github.com/containernetworking/cni v0.0.0-00010101000000-000000000000
	github.com/docker/libkv v0.2.2-0.20211217151845-dfacc563de57
	github.com/golang/mock v1.6.0
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.9.0
	github.com/vishvananda/netlink v0.0.0-20170524205439-99091d844046
	golang.org/x/tools v0.24.0
)

require (
	github.com/coreos/go-iptables v0.8.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/onsi/gomega v1.34.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	go.etcd.io/bbolt v1.3.11 // indirect
	golang.org/x/mod v0.20.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/containernetworking/cni => github.com/aaithal/cni v0.4.1-0.20170403214917-0db5cd54f92d
