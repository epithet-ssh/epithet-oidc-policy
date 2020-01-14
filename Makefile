CMD_GO=$(shell find cmd -type f -name '*.go')
PKG_GO=$(shell find pkg -type f -name '*.go')

.PHONY: all
all: test build		## run tests and build binaries

internal/agent/agent.pb.go:
	mkdir -p internal/agent
	protoc -I ./proto agent.proto --go_out=plugins=grpc:internal/agent

.PHONY: protoc
protoc: internal/agent/agent.pb.go

epithet-oidc: internal/agent/agent.pb.go cmd/epithet-oidc/*
	go build ./cmd/epithet-oidc

epithet-oidc-policy: $(CMD_GO) $(PKG_GO)
	go build -o epithet-oidc-policy ./cmd

.PHONY: build
build: epithet-oidc-policy epithet-oidc protoc

.PHONY: clean-all
clean-all: clean
	go clean -cache
	go clean -modcache

.PHONY: test
test: test-support	## build and run test plumbing
	go test ./...

.PHONY: test-support
test-support: protoc

.PHONY: clean
clean:			## clean all local resources
	go clean ./...
	go clean -testcache
	rm -f epithet-*

.PHONY: help
help:			## Show this help.
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'
