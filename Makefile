.PHONY: all
all: test build		## run tests and build binaries

internal/agent/agent.pb.go:
	mkdir -p internal/agent
	protoc -I ./proto agent.proto --go_out=plugins=grpc:internal/agent

.PHONY: protoc
protoc: internal/agent/agent.pb.go

epithet-oidc: internal/agent/agent.pb.go cmd/epithet-oidc/*
	go build ./cmd/epithet-oidc

.PHONY: build
build: epithet-oidc protoc

.PHONY: clean
clean:			## clean all local resources
	rm -f epithet-*

.PHONY: help
help:			## Show this help.
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'
