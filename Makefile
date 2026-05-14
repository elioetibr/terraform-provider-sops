.PHONY: build test lint tidy install

GO   ?= go
BINARY = terraform-provider-sops
VERSION ?= dev
OS   ?= $(shell go env GOOS)
ARCH ?= $(shell go env GOARCH)

build:
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o $(BINARY)

test:
	$(GO) test -race -count=1 ./...

testacc:
	TF_ACC=1 $(GO) test -race -count=1 -timeout 30m ./...

lint:
	golangci-lint run

tidy:
	$(GO) mod tidy

install: build
	mkdir -p ~/.terraform.d/plugins/registry.terraform.io/elioseverojunior/sops/$(VERSION)/$(OS)_$(ARCH)
	cp $(BINARY) ~/.terraform.d/plugins/registry.terraform.io/elioseverojunior/sops/$(VERSION)/$(OS)_$(ARCH)/
