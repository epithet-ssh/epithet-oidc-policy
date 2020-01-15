.PHONY: all
all: test build

.PHONY: generate
generate:
	go generate ./...

epithet-oidc-plugin: generate cmd/epithet-oidc-plugin/* pkg/oidc/* internal/agent/*
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
test: generate
	go test ./...


.PHONY: clean
clean:
	go clean ./...
	go clean -testcache
	rm -f epithet-*
	rm -f ./internal/agent/agent.pb.go
