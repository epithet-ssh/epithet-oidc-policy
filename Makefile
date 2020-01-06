.PHONY: all
all: test build		## run tests and build binaries

epithet-oidc-policy: app/*
	mkdir -p build
	go build -o build/epithet-oidc-policy ./app

.PHONY: build
build: epithet-oidc-policy

.PHONY: test
test:			## build and run test plumbing
	go test ./app/

.PHONY: clean
clean:			## clean all local resources
	rm -rf build

.PHONY: help
help:			## Show this help.
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'
