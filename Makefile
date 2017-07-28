SOURCEDIR=./pkg ./plugins
SOURCES := $(shell find $(SOURCEDIR) -name '*.go')
ROOT := $(shell pwd)
LOCAL_ENI_PLUGIN_BINARY=bin/plugins/ecs-eni
LOCAL_IPAM_PLUGIN_BINARY=bin/plugins/ecs-ipam
LOCAL_BRIDGE_PLUGIN_BINARY=bin/plugins/ecs-bridge
GIT_PORCELAIN=$(shell git status --porcelain | wc -l)
GIT_SHORT_HASH=$(shell git rev-parse --short HEAD)
VERSION=$(shell cat $(ROOT)/VERSION)
GO_EXECUTABLE=$(shell which go)

.PHONY: get-deps
get-deps:
	go get github.com/golang/mock/gomock
	go get github.com/golang/mock/mockgen
	go get golang.org/x/tools/cmd/goimports
	go get github.com/tools/godep

.PHONY: plugins
plugins: $(LOCAL_ENI_PLUGIN_BINARY) $(LOCAL_IPAM_PLUGIN_BINARY) $(LOCAL_BRIDGE_PLUGIN_BINARY)

$(LOCAL_ENI_PLUGIN_BINARY): $(SOURCES)
	GOOS=linux CGO_ENABLED=0 go build -installsuffix cgo -a -ldflags "\
	     -X github.com/aws/amazon-ecs-cni-plugins/pkg/version.GitShortHash=$(GIT_SHORT_HASH) \
	     -X github.com/aws/amazon-ecs-cni-plugins/pkg/version.GitPorcelain=$(GIT_PORCELAIN) \
	     -X github.com/aws/amazon-ecs-cni-plugins/pkg/version.Version=$(VERSION) -s" \
	     -o ${ROOT}/${LOCAL_ENI_PLUGIN_BINARY} github.com/aws/amazon-ecs-cni-plugins/plugins/eni
	@echo "Built eni plugin"

$(LOCAL_IPAM_PLUGIN_BINARY): $(SOURCES)
	GOOS=linux CGO_ENABLED=0 go build -installsuffix cgo -a -ldflags "\
	     -X github.com/aws/amazon-ecs-cni-plugins/pkg/version.GitShortHash=$(GIT_SHORT_HASH) \
	     -X github.com/aws/amazon-ecs-cni-plugins/pkg/version.GitPorcelain=$(GIT_PORCELAIN) \
	     -X github.com/aws/amazon-ecs-cni-plugins/pkg/version.Version=$(VERSION) -s" \
	     -o ${ROOT}/${LOCAL_IPAM_PLUGIN_BINARY} github.com/aws/amazon-ecs-cni-plugins/plugins/ipam
	@echo "Built ipam plugin"

$(LOCAL_BRIDGE_PLUGIN_BINARY): $(SOURCES)
	GOOS=linux CGO_ENABLED=0 go build -installsuffix cgo -a -ldflags "\
	     -X github.com/aws/amazon-ecs-cni-plugins/pkg/version.GitShortHash=$(GIT_SHORT_HASH) \
	     -X github.com/aws/amazon-ecs-cni-plugins/pkg/version.GitPorcelain=$(GIT_PORCELAIN) \
	     -X github.com/aws/amazon-ecs-cni-plugins/pkg/version.Version=$(VERSION) -s" \
	     -o ${ROOT}/${LOCAL_BRIDGE_PLUGIN_BINARY} github.com/aws/amazon-ecs-cni-plugins/plugins/ecs-bridge
	@echo "Built bridge plugin"

.PHONY: generate
generate: $(SOURCES)
	go generate -x ./pkg/... ./plugins/...

.PHONY: unit-test integration-test e2e-test
unit-test: $(SOURCES)
	go test -v -cover -race -timeout 10s ./pkg/... ./plugins/...

integration-test: $(SOURCE)
	go test -v -tags integration -race -timeout 10s ./pkg/... ./plugins/...

e2e-test:  $(SOURCE) plugins
	sudo -E CNI_PATH=${ROOT}/bin/plugins ${GO_EXECUTABLE} test -v -tags e2e -race -timeout 10s ./plugins/...

.PHONY: clean
clean:
	rm -rf ${ROOT}/bin ||:
