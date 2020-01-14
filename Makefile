.PHONY: all
all: test build

internal/agent/agent.pb.go: proto/agent.proto
	mkdir -p internal/agent
	protoc -I ./proto agent.proto --go_out=plugins=grpc:internal/agent

.PHONY: protoc
protoc: internal/agent/agent.pb.go

epithet-oidc-plugin: cmd/epithet-oidc-plugin/* pkg/oidc/* internal/agent/*
	go build -o epithet-oidc-plugin ./cmd/epithet-oidc-plugin

epithet-oidc-policy: cmd/epithet-oidc-policy/* pkg/authenticator/* pkg/authorizer/* pkg/policyserver/*
	go build -o epithet-oidc-policy ./cmd/epithet-oidc-policy

.PHONY: build
build: epithet-oidc-policy epithet-oidc-plugin

.PHONY: clean-all
clean-all: clean
	go clean -cache
	go clean -modcache

.PHONY: test
test: test-support
	go test ./...

.PHONY: test-support
test-support: protoc

.PHONY: clean
clean:
	go clean ./...
	go clean -testcache
	rm -f epithet-*
