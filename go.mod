module github.com/aws/amazon-ecs-cni-plugins

go 1.22.0

require (
	github.com/aws/aws-sdk-go-v2 v1.30.5
	github.com/aws/aws-sdk-go-v2/config v1.27.35
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.13
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.177.4
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
	github.com/aws/aws-sdk-go-v2/credentials v1.17.33 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.22.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.26.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.30.8 // indirect
	github.com/aws/smithy-go v1.20.4 // indirect
	github.com/coreos/go-iptables v0.8.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
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
