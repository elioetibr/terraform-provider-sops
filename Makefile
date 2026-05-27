HOSTNAME=registry.terraform.io
NAMESPACE=elioetibr
MODULE		:= $(shell go list -m)
NAME		:= $(patsubst terraform-provider-%,%,$(notdir $(MODULE)))
BINARY		:= terraform-provider-$(NAME)

GO   ?= go
VERSION ?= dev
OS   ?= $(shell go env GOOS)
ARCH ?= $(shell go env GOARCH)

.PHONY: deps
deps: ## Install deps packages
	@echo "$(GREEN)Install shadow vettool package...$(NC)"
	go install golang.org/x/tools/go/analysis/passes/shadow/cmd/shadow@latest

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
fmt: ## Format code
	@echo "$(GREEN)Formatting code...$(NC)"
	@go fmt $(PKG_PATH)
	@gofmt -s -w .
	@find . -name '*.go' | xargs goimports -w -local $(NAME)

.PHONY: vet
vet: deps ## Run go vet, including the shadow analyzer
	@echo "$(GREEN)Running go vet...$(NC)"
	go vet ./...
	@echo "$(GREEN)Running go vet (shadow analyzer)...$(NC)"
	go vet -vettool=$(shell go env GOPATH)/bin/shadow ./...

.PHONY: clean
clean:
	rm -f $(BINARY)

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: docs
docs:
	$(GO) run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate --provider-name $(NAME)

.PHONY: lint
lint: ## Run golangci-lint
	@echo "$(GREEN)Running linters...$(NC)"
	@gcl=""; \
	for cand in \
		"$$(command -v golangci-lint 2>/dev/null || true)" \
		"$$(go env GOPATH)/bin/golangci-lint" \
		"$$(brew --prefix 2>/dev/null || true)/bin/golangci-lint"; do \
		if [ -x "$$cand" ] && go version -m "$$cand" 2>/dev/null | grep -q 'golangci-lint/v2'; then \
			gcl="$$cand"; break; \
		fi; \
	done; \
	if [ -z "$$gcl" ]; then \
		if [ "$(UNAME_S)" = "Darwin" ] && command -v brew >/dev/null 2>&1; then \
			echo "$(YELLOW)Installing golangci-lint via Homebrew...$(NC)"; \
			brew install golangci-lint; \
			gcl="$$(brew --prefix)/bin/golangci-lint"; \
		else \
			echo "$(YELLOW)Installing golangci-lint $(GOLANGCI_LINT_VERSION) via go install...$(NC)"; \
			go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); \
			gcl="$$(go env GOPATH)/bin/golangci-lint"; \
		fi; \
	fi; \
	echo "$(GREEN)Using $$gcl$(NC)"; \
	"$$gcl" run ./...

.PHONY: all
all: fmt vet build test docs

ci: fmt lint test build ## Run the full local CI: fmt, lint, test, build
	@echo "$(GREEN)CI passed.$(NC)"
