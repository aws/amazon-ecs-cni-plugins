SOURCEDIR=./pkg ./plugins
SOURCES := $(shell find $(SOURCEDIR) -name '*.go')
ROOT := $(shell pwd)

.PHONY: generate
generate: $(SOURCES)
	go generate -x ./pkg/... ./plugins/...

.PHONY: unit-tests
unit-tests: $(SOURCES)
	go test -v -cover -timeout 10s ./pkg/... ./plugins/...
