HOSTNAME=registry.terraform.io
NAMESPACE=elioetibr
NAME=sops
BINARY = terraform-provider-${NAME}

GO   ?= go
VERSION ?= dev
OS   ?= $(shell go env GOOS)
ARCH ?= $(shell go env GOARCH)

.PHONY: build
build:
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o $(BINARY)

.PHONY: install
install: build
	mkdir -p ~/.terraform.d/plugins/$(HOSTNAME)/$(NAMESPACE)/$(NAME)/$(VERSION)/$(OS_ARCH)
	cp $(BINARY) ~/.terraform.d/plugins/$(HOSTNAME)/$(NAMESPACE)/$(NAME)/$(VERSION)/$(OS_ARCH)/

.PHONY: test
test:
	$(GO) test -race -count=1 ./...

.PHONY: testacc
testacc:
	TF_ACC=1 $(GO) test -race -count=1 -timeout 30m ./...

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: clean
clean:
	rm -f $(BINARY)

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: docs
docs:
	tfplugindocs generate --provider-name $(NAME)

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: all
all: fmt vet build test docs
