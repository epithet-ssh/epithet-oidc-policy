CMD_GO=$(shell find cmd -type f -name '*.go')
PKG_GO=$(shell find pkg -type f -name '*.go')

.PHONY: all
all: test build		## run tests and build binaries

epithet-oidc-policy: $(CMD_GO) $(PKG_GO)
	go build -o epithet-oidc-policy ./cmd

.PHONY: build
build: epithet-oidc-policy

.PHONY: test
test:	## build and run test plumbing
	go test ./...

.PHONY: clean
clean:			## clean all local resources
	go clean ./...
	go clean -testcache
	rm -f epithet-*

.PHONY: clean-all
clean-all: clean
	go clean -cache
	go clean -modcache

.PHONY: help
help:			## Show this help.
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'
