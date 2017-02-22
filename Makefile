SOURCEDIR=./pkg ./plugins
SOURCES := $(shell find $(SOURCEDIR) -name '*.go')
ROOT := $(shell pwd)

.PHONY: get-deps
get-deps:
	go get github.com/golang/mock/gomock
	go get github.com/golang/mock/mockgen
	go get golang.org/x/tools/cmd/goimports
	go get github.com/tools/godep

.PHONY: plugins
plugins: eni

.PHONY: eni
eni: $(SOURCES)
	GOOS=linux CGO_ENABLED=0 go build -installsuffix cgo -a -ldflags '-s' -o ${ROOT}/bin/eni github.com/aws/amazon-ecs-cni-plugins/plugins/eni
	@echo "Built eni plugin"

.PHONY: generate
generate: $(SOURCES)
	go generate -x ./pkg/... ./plugins/...

.PHONY: unit-tests
unit-tests: $(SOURCES)
	go test -cover -timeout 10s ./pkg/... ./plugins/...

.PHONY: clean
clean:
	rm -rf ${ROOT}/bin ||:
