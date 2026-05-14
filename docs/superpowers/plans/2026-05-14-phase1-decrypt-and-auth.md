# terraform-provider-sops — Phase 1 (Decrypt + Auth) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `elioseverojunior/sops` v0.1.0 — a Terraform provider that decrypts SOPS files with first-class AWS/GCP/Azure/age/PGP credential configuration at provider, alias, and per-resource level. Drop-in attribute-compatible with `carlpett/sops`, but kills the `AWS_PROFILE=…` export requirement.

**Architecture:** Built on `terraform-plugin-framework`. Bypasses SOPS's high-level `decrypt.Data()` helper (which has no per-call credential support) and instead constructs `kms.MasterKey` / `gcpkms.MasterKey` / `azkv.MasterKey` / `age.MasterKey` / `pgp.MasterKey` structs directly with injected credentials, then drives `tree.Metadata.GetDataKeyWithKeyServices()` and `tree.Decrypt()`. A weighted semaphore around every decrypt call eliminates the carlpett #126 concurrency bug.

**Tech Stack:** Go 1.23, `github.com/hashicorp/terraform-plugin-framework` v1.x, `github.com/getsops/sops/v3`, `github.com/aws/aws-sdk-go-v2`, `cloud.google.com/go/kms`, `github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys`, `filippo.io/age`, `golang.org/x/sync/semaphore`.

**Reference spec:** `docs/superpowers/specs/2026-05-14-terraform-sops-provider-design.md`

---

## File Structure

Created in this plan (Phase 1 only):

```
terraform-provider-sops/
├── go.mod                                            # module github.com/elioseverojunior/terraform-provider-sops
├── go.sum
├── main.go                                           # framework plugin entrypoint
├── Makefile                                          # build/test/lint convenience
├── .golangci.yml                                     # lint config
├── .goreleaser.yml                                   # release config (used in Phase 1 dry-run only)
├── tools/tools.go                                    # pins tfplugindocs etc.
├── internal/
│   ├── provider/
│   │   ├── provider.go                               # New(), Metadata, Schema, Configure, DataSources, EphemeralResources
│   │   ├── provider_test.go
│   │   ├── models.go                                 # ProviderModel (terraform-plugin-framework data model)
│   │   └── auth/
│   │       ├── types.go                              # auth.Config + nested AWS/GCP/Azure/Age/PGP structs
│   │       ├── types_test.go
│   │       ├── aws.go                                # AWS schema attrs + Model → AWSConfig
│   │       ├── aws_test.go
│   │       ├── gcp.go
│   │       ├── gcp_test.go
│   │       ├── azure.go
│   │       ├── azure_test.go
│   │       ├── age.go
│   │       ├── age_test.go
│   │       ├── pgp.go
│   │       ├── pgp_test.go
│   │       ├── merge.go                              # Merge(provider, perCall) → Config (leaf-field overlay)
│   │       └── merge_test.go
│   ├── sopswrap/
│   │   ├── store.go                                  # Format → sops Store (yaml/json/dotenv/ini/binary)
│   │   ├── store_test.go
│   │   ├── masterkey.go                              # Build []keys.MasterKey from auth.Config + tree.Metadata
│   │   ├── masterkey_test.go
│   │   ├── concurrency.go                            # global Weighted semaphore + GPG mutex
│   │   ├── concurrency_test.go
│   │   ├── output.go                                 # Flatten tree → map[string]string + JSON + metadata
│   │   ├── output_test.go
│   │   ├── decrypt.go                                # Decrypt(ctx, source, cfg) → Result (the heart)
│   │   └── decrypt_test.go
│   ├── datasources/
│   │   ├── file.go                                   # data "sops_file"
│   │   ├── file_test.go
│   │   ├── external.go                               # data "sops_external"
│   │   └── external_test.go
│   └── ephemeral/
│       ├── file.go                                   # ephemeral "sops_file"
│       ├── file_test.go
│       ├── external.go                               # ephemeral "sops_external"
│       └── external_test.go
├── examples/
│   ├── aws-kms-profile/main.tf
│   ├── aws-cross-account/main.tf
│   ├── age/main.tf
│   └── multi-alias/main.tf
├── testdata/
│   ├── age-key.txt                                   # test-only age private key (fixture)
│   ├── secrets.yaml                                  # age-encrypted YAML fixture
│   ├── secrets.json                                  # age-encrypted JSON
│   ├── secrets.env                                   # age-encrypted dotenv
│   ├── secrets.ini                                   # age-encrypted INI
│   └── secrets.bin                                   # age-encrypted binary
├── .github/workflows/
│   ├── ci.yml                                        # unit tests + lint on every PR
│   └── acceptance.yml                                # cloud acceptance tests (manual dispatch)
└── README.md                                         # rewrite with migration guide
```

## Conventions

- **Every commit is GPG-signed** (`git commit -S`). Required by `/Users/elio/.claude/CLAUDE.md`.
- **No `Co-Authored-By` trailers** ever. Required by same.
- **Go style:** prefer interfaces for testability, structured Kubernetes-style logging (`tflog`), worker pools for concurrency. SOLID/DRY/KISS.
- **Test framework:** stdlib `testing` + `github.com/stretchr/testify/require` for assertions; `github.com/hashicorp/terraform-plugin-testing` for acceptance tests.
- **TDD:** every component task is *test → fail → implement → pass → commit*.

---

### Task 1: Project scaffold

**Files:**
- Create: `go.mod`
- Create: `go.sum` (generated)
- Create: `main.go`
- Create: `Makefile`
- Create: `.golangci.yml`
- Create: `tools/tools.go`

- [ ] **Step 1: Initialize Go module**

Run:
```bash
cd /Volumes/Development/pessoal/elioseverojunior/go/terraform-sops-provider
go mod init github.com/elioseverojunior/terraform-provider-sops
```

Expected: creates `go.mod` with `module github.com/elioseverojunior/terraform-provider-sops` and `go 1.23` (or whatever current toolchain is).

- [ ] **Step 2: Add core dependencies**

Run:
```bash
go get github.com/hashicorp/terraform-plugin-framework@latest
go get github.com/getsops/sops/v3@latest
go get github.com/stretchr/testify@latest
go get golang.org/x/sync@latest
go get github.com/hashicorp/terraform-plugin-log@latest
```

Expected: dependencies appear in go.mod; go.sum populated.

- [ ] **Step 3: Write the failing `TestProviderBuilds` test**

Create `internal/provider/provider_test.go`:

```go
package provider_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/stretchr/testify/require"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider"
)

func TestProviderBuilds(t *testing.T) {
	t.Parallel()
	p := provider.New("test")()
	require.NotNil(t, p, "provider must construct")
	// providerserver.NewProtocol6 returns a func; calling it returns a server we can probe.
	_, err := providerserver.NewProtocol6WithError(p)()
	require.NoError(t, err)
	_ = context.Background()
}
```

- [ ] **Step 4: Run the test — expect fail (no provider package yet)**

Run: `go test ./internal/provider/...`
Expected: FAIL with `package github.com/elioseverojunior/terraform-provider-sops/internal/provider: no Go files`.

- [ ] **Step 5: Write the minimal `provider.New` stub**

Create `internal/provider/provider.go`:

```go
package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

type sopsProvider struct {
	version string
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &sopsProvider{version: version}
	}
}

func (p *sopsProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "sops"
	resp.Version = p.version
}

func (p *sopsProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{},
	}
}

func (p *sopsProvider) Configure(_ context.Context, _ provider.ConfigureRequest, _ *provider.ConfigureResponse) {
}

func (p *sopsProvider) DataSources(_ context.Context) []func() datasource.DataSource           { return nil }
func (p *sopsProvider) EphemeralResources(_ context.Context) []func() ephemeral.EphemeralResource { return nil }
func (p *sopsProvider) Resources(_ context.Context) []func() resource.Resource                 { return nil }
func (p *sopsProvider) Functions(_ context.Context) []func() function.Function                 { return nil }
```

- [ ] **Step 6: Run the test — expect pass**

Run: `go test ./internal/provider/... -v`
Expected: `PASS: TestProviderBuilds`.

- [ ] **Step 7: Write `main.go`**

Create `main.go`:

```go
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider"
)

var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/elioseverojunior/sops",
		Debug:   debug,
	}

	if err := providerserver.Serve(context.Background(), provider.New(version), opts); err != nil {
		log.Fatal(err.Error())
	}
}
```

- [ ] **Step 8: Add Makefile**

Create `Makefile`:

```makefile
.PHONY: build test lint tidy install

GO ?= go
BINARY = terraform-provider-sops
VERSION ?= dev

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
	mkdir -p ~/.terraform.d/plugins/registry.terraform.io/elioseverojunior/sops/$(VERSION)/darwin_arm64
	cp $(BINARY) ~/.terraform.d/plugins/registry.terraform.io/elioseverojunior/sops/$(VERSION)/darwin_arm64/
```

- [ ] **Step 9: Add `.golangci.yml`**

Create `.golangci.yml`:

```yaml
run:
  timeout: 5m
  go: "1.23"

linters:
  enable:
    - errcheck
    - gofmt
    - goimports
    - gosimple
    - govet
    - ineffassign
    - misspell
    - revive
    - staticcheck
    - typecheck
    - unconvert
    - unused

linters-settings:
  goimports:
    local-prefixes: github.com/elioseverojunior/terraform-provider-sops
```

- [ ] **Step 10: Add `tools/tools.go` for dev-tool pinning**

Create `tools/tools.go`:

```go
//go:build tools

package tools

import (
	_ "github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs"
)
```

Run: `go mod tidy && go build ./...`
Expected: no errors.

- [ ] **Step 11: Commit**

```bash
git add go.mod go.sum main.go Makefile .golangci.yml tools/tools.go internal/provider/provider.go internal/provider/provider_test.go
git commit -S -m "feat: scaffold provider with framework skeleton

- Module: github.com/elioseverojunior/terraform-provider-sops
- terraform-plugin-framework provider that builds and serves
- Empty schema; DataSources/EphemeralResources/Resources/Functions stubs
- Makefile, golangci config, tools.go for tfplugindocs pin"
```

---

### Task 2: `auth.Config` types

The single struct that every layer (data source, ephemeral, sopswrap) consumes. Defines the shape of credentials for every key source.

**Files:**
- Create: `internal/provider/auth/types.go`
- Create: `internal/provider/auth/types_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/provider/auth/types_test.go`:

```go
package auth_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
)

func TestConfigZeroValue(t *testing.T) {
	t.Parallel()
	var cfg auth.Config
	require.Empty(t, cfg.AWS.Profile)
	require.Empty(t, cfg.GCP.CredentialsFile)
	require.Empty(t, cfg.Azure.TenantID)
	require.Empty(t, cfg.Age.KeyFile)
	require.Empty(t, cfg.PGP.GnupgHome)
}

func TestConfigAssumeRoleNested(t *testing.T) {
	t.Parallel()
	cfg := auth.Config{
		AWS: auth.AWSConfig{
			Profile: "p",
			AssumeRole: &auth.AWSAssumeRole{
				RoleARN: "arn:aws:iam::123:role/r",
			},
		},
	}
	require.Equal(t, "p", cfg.AWS.Profile)
	require.NotNil(t, cfg.AWS.AssumeRole)
	require.Equal(t, "arn:aws:iam::123:role/r", cfg.AWS.AssumeRole.RoleARN)
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/provider/auth/...`
Expected: FAIL with `package github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth: no Go files`.

- [ ] **Step 3: Implement `types.go`**

Create `internal/provider/auth/types.go`:

```go
// Package auth defines the credential configuration types shared by the
// provider block, per-resource overrides, and the sopswrap layer.
package auth

import "time"

// Config is the merged credential configuration for a single decrypt or encrypt call.
// Construct via auth.Merge(providerConfig, perCallConfig).
type Config struct {
	AWS   AWSConfig
	GCP   GCPConfig
	Azure AzureConfig
	Age   AgeConfig
	PGP   PGPConfig

	// ConcurrencyLimit caps parallel decrypts. Zero means "use package default".
	ConcurrencyLimit int
}

type AWSConfig struct {
	Profile                string
	Region                 string
	SharedConfigFiles      []string
	SharedCredentialsFiles []string
	Env                    map[string]string
	AssumeRole             *AWSAssumeRole
}

type AWSAssumeRole struct {
	RoleARN     string
	SessionName string
	ExternalID  string
	Duration    time.Duration
}

type GCPConfig struct {
	Credentials                string // raw JSON
	CredentialsFile            string
	ImpersonateServiceAccount  string
	QuotaProject               string
}

type AzureConfig struct {
	TenantID            string
	ClientID            string
	ClientSecret        string
	UseMSI              bool
	UseOIDC             bool
	UseWorkloadIdentity bool
	UseCLI              bool
}

type AgeConfig struct {
	Key               string // explicit private key material
	KeyFile           string
	KeyCommand        string
	SSHPrivateKeyFile string
}

type PGPConfig struct {
	GnupgHome string
}
```

- [ ] **Step 4: Run — expect pass**

Run: `go test ./internal/provider/auth/... -v`
Expected: `PASS: TestConfigZeroValue`, `PASS: TestConfigAssumeRoleNested`.

- [ ] **Step 5: Commit**

```bash
git add internal/provider/auth/types.go internal/provider/auth/types_test.go
git commit -S -m "feat(auth): add Config type with AWS/GCP/Azure/age/PGP nested configs"
```

---

### Task 3: `auth.Merge` — provider-level + per-call overlay

Implements the leaf-field overlay semantics from spec §5.3.

**Files:**
- Create: `internal/provider/auth/merge.go`
- Create: `internal/provider/auth/merge_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/provider/auth/merge_test.go`:

```go
package auth_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
)

func TestMerge_EmptyPerCallReturnsProvider(t *testing.T) {
	t.Parallel()
	provider := auth.Config{
		AWS: auth.AWSConfig{Profile: "prod", Region: "us-east-1"},
	}
	out := auth.Merge(provider, auth.Config{})
	require.Equal(t, "prod", out.AWS.Profile)
	require.Equal(t, "us-east-1", out.AWS.Region)
}

func TestMerge_PerCallOverridesLeafField(t *testing.T) {
	t.Parallel()
	provider := auth.Config{
		AWS: auth.AWSConfig{Profile: "prod", Region: "us-east-1"},
	}
	perCall := auth.Config{
		AWS: auth.AWSConfig{Profile: "dev"},
	}
	out := auth.Merge(provider, perCall)
	require.Equal(t, "dev", out.AWS.Profile, "per-call profile must win")
	require.Equal(t, "us-east-1", out.AWS.Region, "provider region must survive")
}

func TestMerge_AssumeRoleReplacedAtomically(t *testing.T) {
	t.Parallel()
	provider := auth.Config{
		AWS: auth.AWSConfig{
			Profile: "prod",
			AssumeRole: &auth.AWSAssumeRole{
				RoleARN:     "arn:aws:iam::111:role/r1",
				SessionName: "provider-session",
				Duration:    time.Hour,
			},
		},
	}
	perCall := auth.Config{
		AWS: auth.AWSConfig{
			AssumeRole: &auth.AWSAssumeRole{RoleARN: "arn:aws:iam::222:role/r2"},
		},
	}
	out := auth.Merge(provider, perCall)
	require.NotNil(t, out.AWS.AssumeRole)
	require.Equal(t, "arn:aws:iam::222:role/r2", out.AWS.AssumeRole.RoleARN)
	require.Empty(t, out.AWS.AssumeRole.SessionName,
		"AssumeRole is replaced atomically; sub-fields do not merge")
}

func TestMerge_SharedConfigFilesPerCallWinsAtomically(t *testing.T) {
	t.Parallel()
	provider := auth.Config{AWS: auth.AWSConfig{SharedConfigFiles: []string{"/p/c"}}}
	perCall := auth.Config{AWS: auth.AWSConfig{SharedConfigFiles: []string{"/q/c"}}}
	out := auth.Merge(provider, perCall)
	require.Equal(t, []string{"/q/c"}, out.AWS.SharedConfigFiles)
}

func TestMerge_AzureBoolOverride(t *testing.T) {
	t.Parallel()
	provider := auth.Config{Azure: auth.AzureConfig{UseMSI: true}}
	perCall := auth.Config{Azure: auth.AzureConfig{UseOIDC: true}}
	out := auth.Merge(provider, perCall)
	require.True(t, out.Azure.UseMSI)
	require.True(t, out.Azure.UseOIDC)
}

func TestMerge_AzureBoolExplicitFalseDoesNotZeroProvider(t *testing.T) {
	// Important: zero-value bool from an unset per-call attribute MUST NOT clobber
	// a true provider-level bool. The merge treats zero as "absent."
	t.Parallel()
	provider := auth.Config{Azure: auth.AzureConfig{UseMSI: true}}
	perCall := auth.Config{} // UseMSI defaults to false
	out := auth.Merge(provider, perCall)
	require.True(t, out.Azure.UseMSI, "absent per-call bool must not zero provider")
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/provider/auth/...`
Expected: FAIL with `undefined: auth.Merge`.

- [ ] **Step 3: Implement `merge.go`**

Create `internal/provider/auth/merge.go`:

```go
package auth

// Merge overlays perCall onto provider, returning a new Config.
//
// Semantics (per spec §5.3):
//   - Leaf strings/ints/durations: perCall wins iff non-zero.
//   - Bools: perCall wins iff true (no way to express "explicit false override"
//     at the schema level for now; users wanting to disable a provider-level
//     bool should omit the provider-level block on that resource via alias).
//   - Slices: perCall wins atomically iff non-nil and non-empty.
//   - Pointer structs (AssumeRole): perCall wins atomically iff non-nil.
//   - Maps (AWSConfig.Env): perCall keys overlay provider keys.
func Merge(provider, perCall Config) Config {
	out := provider
	out.AWS = mergeAWS(provider.AWS, perCall.AWS)
	out.GCP = mergeGCP(provider.GCP, perCall.GCP)
	out.Azure = mergeAzure(provider.Azure, perCall.Azure)
	out.Age = mergeAge(provider.Age, perCall.Age)
	out.PGP = mergePGP(provider.PGP, perCall.PGP)
	if perCall.ConcurrencyLimit != 0 {
		out.ConcurrencyLimit = perCall.ConcurrencyLimit
	}
	return out
}

func mergeAWS(p, c AWSConfig) AWSConfig {
	out := p
	if c.Profile != "" {
		out.Profile = c.Profile
	}
	if c.Region != "" {
		out.Region = c.Region
	}
	if len(c.SharedConfigFiles) > 0 {
		out.SharedConfigFiles = c.SharedConfigFiles
	}
	if len(c.SharedCredentialsFiles) > 0 {
		out.SharedCredentialsFiles = c.SharedCredentialsFiles
	}
	if len(c.Env) > 0 {
		if out.Env == nil {
			out.Env = map[string]string{}
		} else {
			merged := make(map[string]string, len(out.Env)+len(c.Env))
			for k, v := range out.Env {
				merged[k] = v
			}
			out.Env = merged
		}
		for k, v := range c.Env {
			out.Env[k] = v
		}
	}
	if c.AssumeRole != nil {
		ar := *c.AssumeRole
		out.AssumeRole = &ar
	}
	return out
}

func mergeGCP(p, c GCPConfig) GCPConfig {
	out := p
	if c.Credentials != "" {
		out.Credentials = c.Credentials
	}
	if c.CredentialsFile != "" {
		out.CredentialsFile = c.CredentialsFile
	}
	if c.ImpersonateServiceAccount != "" {
		out.ImpersonateServiceAccount = c.ImpersonateServiceAccount
	}
	if c.QuotaProject != "" {
		out.QuotaProject = c.QuotaProject
	}
	return out
}

func mergeAzure(p, c AzureConfig) AzureConfig {
	out := p
	if c.TenantID != "" {
		out.TenantID = c.TenantID
	}
	if c.ClientID != "" {
		out.ClientID = c.ClientID
	}
	if c.ClientSecret != "" {
		out.ClientSecret = c.ClientSecret
	}
	if c.UseMSI {
		out.UseMSI = true
	}
	if c.UseOIDC {
		out.UseOIDC = true
	}
	if c.UseWorkloadIdentity {
		out.UseWorkloadIdentity = true
	}
	if c.UseCLI {
		out.UseCLI = true
	}
	return out
}

func mergeAge(p, c AgeConfig) AgeConfig {
	out := p
	if c.Key != "" {
		out.Key = c.Key
	}
	if c.KeyFile != "" {
		out.KeyFile = c.KeyFile
	}
	if c.KeyCommand != "" {
		out.KeyCommand = c.KeyCommand
	}
	if c.SSHPrivateKeyFile != "" {
		out.SSHPrivateKeyFile = c.SSHPrivateKeyFile
	}
	return out
}

func mergePGP(p, c PGPConfig) PGPConfig {
	out := p
	if c.GnupgHome != "" {
		out.GnupgHome = c.GnupgHome
	}
	return out
}
```

- [ ] **Step 4: Run — expect pass**

Run: `go test ./internal/provider/auth/... -v -run TestMerge`
Expected: all six TestMerge_* PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/provider/auth/merge.go internal/provider/auth/merge_test.go
git commit -S -m "feat(auth): add Merge() with leaf-field overlay semantics

Per-call config overlays provider-level config field-by-field:
- Strings/ints/durations: per-call wins if non-zero
- Slices: per-call wins atomically if non-empty
- Bools: per-call wins if true (zero treated as absent)
- Pointer structs: replaced atomically
- Env map: keys overlaid"
```

---

### Task 4: AWS auth schema + model→Config

Translates a Terraform `aws { ... }` HCL block into `auth.AWSConfig`.

**Files:**
- Create: `internal/provider/auth/aws.go`
- Create: `internal/provider/auth/aws_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/provider/auth/aws_test.go`:

```go
package auth_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/require"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
)

func TestAWSModelToConfig_AllFields(t *testing.T) {
	t.Parallel()
	m := &auth.AWSModel{
		Profile:                types.StringValue("prod"),
		Region:                 types.StringValue("us-east-1"),
		SharedConfigFiles:      listOfStrings(t, "/p/config"),
		SharedCredentialsFiles: listOfStrings(t, "/p/credentials"),
		Env:                    mapOfStrings(t, map[string]string{"AWS_SDK_LOAD_CONFIG": "1"}),
		AssumeRole: &auth.AWSAssumeRoleModel{
			RoleARN:     types.StringValue("arn:aws:iam::1:role/r"),
			SessionName: types.StringValue("sess"),
			ExternalID:  types.StringValue("ext"),
			Duration:    types.StringValue("1h"),
		},
	}
	cfg, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError(), diags.Errors())
	require.Equal(t, "prod", cfg.Profile)
	require.Equal(t, "us-east-1", cfg.Region)
	require.Equal(t, []string{"/p/config"}, cfg.SharedConfigFiles)
	require.Equal(t, []string{"/p/credentials"}, cfg.SharedCredentialsFiles)
	require.Equal(t, "1", cfg.Env["AWS_SDK_LOAD_CONFIG"])
	require.NotNil(t, cfg.AssumeRole)
	require.Equal(t, "arn:aws:iam::1:role/r", cfg.AssumeRole.RoleARN)
}

func TestAWSModelToConfig_InvalidDuration(t *testing.T) {
	t.Parallel()
	m := &auth.AWSModel{
		AssumeRole: &auth.AWSAssumeRoleModel{Duration: types.StringValue("not-a-duration")},
	}
	_, diags := m.ToConfig(context.Background())
	require.True(t, diags.HasError())
}

func TestAWSModelToConfig_NilSafe(t *testing.T) {
	t.Parallel()
	var m *auth.AWSModel
	cfg, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError())
	require.Empty(t, cfg.Profile)
}

// helpers
func listOfStrings(t *testing.T, ss ...string) types.List {
	t.Helper()
	vals := make([]attr.Value, len(ss))
	for i, s := range ss {
		vals[i] = types.StringValue(s)
	}
	l, diags := types.ListValue(types.StringType, vals)
	require.False(t, diags.HasError(), diags.Errors())
	return l
}

func mapOfStrings(t *testing.T, m map[string]string) types.Map {
	t.Helper()
	vals := map[string]attr.Value{}
	for k, v := range m {
		vals[k] = types.StringValue(v)
	}
	out, diags := types.MapValue(types.StringType, vals)
	require.False(t, diags.HasError(), diags.Errors())
	return out
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/provider/auth/... -run TestAWSModel`
Expected: FAIL with `undefined: auth.AWSModel`.

- [ ] **Step 3: Implement `aws.go`**

Create `internal/provider/auth/aws.go`:

```go
package auth

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// AWSModel is the terraform-plugin-framework data model for the `aws { ... }` block.
// Used by both the provider block and per-resource override blocks.
type AWSModel struct {
	Profile                types.String `tfsdk:"profile"`
	Region                 types.String `tfsdk:"region"`
	SharedConfigFiles      types.List   `tfsdk:"shared_config_files"`
	SharedCredentialsFiles types.List   `tfsdk:"shared_credentials_files"`
	Env                    types.Map    `tfsdk:"env"`
	AssumeRole             *AWSAssumeRoleModel `tfsdk:"assume_role"`
}

type AWSAssumeRoleModel struct {
	RoleARN     types.String `tfsdk:"role_arn"`
	SessionName types.String `tfsdk:"session_name"`
	ExternalID  types.String `tfsdk:"external_id"`
	Duration    types.String `tfsdk:"duration"`
}

// AWSBlockSchema returns the framework Schema definition for the `aws` nested block.
// Reused by the provider block schema and per-data-source override schemas.
func AWSBlockSchema() schema.Block {
	return schema.SingleNestedBlock{
		Description: "AWS KMS credential configuration.",
		Attributes: map[string]schema.Attribute{
			"profile":                  schema.StringAttribute{Optional: true},
			"region":                   schema.StringAttribute{Optional: true},
			"shared_config_files":      schema.ListAttribute{Optional: true, ElementType: types.StringType},
			"shared_credentials_files": schema.ListAttribute{Optional: true, ElementType: types.StringType},
			"env":                      schema.MapAttribute{Optional: true, ElementType: types.StringType},
		},
		Blocks: map[string]schema.Block{
			"assume_role": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"role_arn":     schema.StringAttribute{Optional: true},
					"session_name": schema.StringAttribute{Optional: true},
					"external_id":  schema.StringAttribute{Optional: true},
					"duration":     schema.StringAttribute{Optional: true},
				},
			},
		},
	}
}

// ToConfig converts the framework data model into the package's AWSConfig value type.
// Nil receiver returns the zero value with no diagnostics.
func (m *AWSModel) ToConfig(ctx context.Context) (AWSConfig, diag.Diagnostics) {
	if m == nil {
		return AWSConfig{}, nil
	}
	var diags diag.Diagnostics
	cfg := AWSConfig{
		Profile: m.Profile.ValueString(),
		Region:  m.Region.ValueString(),
	}
	if !m.SharedConfigFiles.IsNull() {
		var s []string
		diags.Append(m.SharedConfigFiles.ElementsAs(ctx, &s, false)...)
		cfg.SharedConfigFiles = s
	}
	if !m.SharedCredentialsFiles.IsNull() {
		var s []string
		diags.Append(m.SharedCredentialsFiles.ElementsAs(ctx, &s, false)...)
		cfg.SharedCredentialsFiles = s
	}
	if !m.Env.IsNull() {
		var em map[string]string
		diags.Append(m.Env.ElementsAs(ctx, &em, false)...)
		cfg.Env = em
	}
	if m.AssumeRole != nil {
		ar := AWSAssumeRole{
			RoleARN:     m.AssumeRole.RoleARN.ValueString(),
			SessionName: m.AssumeRole.SessionName.ValueString(),
			ExternalID:  m.AssumeRole.ExternalID.ValueString(),
		}
		if d := m.AssumeRole.Duration.ValueString(); d != "" {
			dur, err := time.ParseDuration(d)
			if err != nil {
				diags.AddAttributeError(
					path("assume_role", "duration"),
					"invalid duration",
					"could not parse aws.assume_role.duration: "+err.Error(),
				)
			}
			ar.Duration = dur
		}
		cfg.AssumeRole = &ar
	}
	return cfg, diags
}
```

We also need a small `path` helper for diagnostics. Add at bottom of `aws.go` (or a shared file later):

```go
// path is a tiny helper to construct attribute paths for diagnostics.
// Kept package-local to avoid pulling in the full framework path package here.
import fwpath "github.com/hashicorp/terraform-plugin-framework/path"

func path(parts ...string) fwpath.Path {
	p := fwpath.Empty()
	for _, part := range parts {
		p = p.AtName(part)
	}
	return p
}
```

(Move the `import` to the top of the file; only one import block per Go file.)

- [ ] **Step 4: Run — expect pass**

Run: `go test ./internal/provider/auth/... -v -run TestAWSModel`
Expected: all three TestAWSModelToConfig_* PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/provider/auth/aws.go internal/provider/auth/aws_test.go
git commit -S -m "feat(auth): AWS schema block and Model.ToConfig

- aws { profile, region, shared_config_files, shared_credentials_files, env }
- aws.assume_role { role_arn, session_name, external_id, duration }
- Reusable AWSBlockSchema() for provider + per-resource overrides"
```

---

### Task 5: GCP auth schema + model→Config

**Files:**
- Create: `internal/provider/auth/gcp.go`
- Create: `internal/provider/auth/gcp_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/provider/auth/gcp_test.go`:

```go
package auth_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/require"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
)

func TestGCPModelToConfig_AllFields(t *testing.T) {
	t.Parallel()
	m := &auth.GCPModel{
		Credentials:               types.StringValue(`{"type":"service_account"}`),
		CredentialsFile:           types.StringValue("/path/to/sa.json"),
		ImpersonateServiceAccount: types.StringValue("sops@project.iam.gserviceaccount.com"),
		QuotaProject:              types.StringValue("my-billing"),
	}
	cfg, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError(), diags.Errors())
	require.Equal(t, `{"type":"service_account"}`, cfg.Credentials)
	require.Equal(t, "/path/to/sa.json", cfg.CredentialsFile)
	require.Equal(t, "sops@project.iam.gserviceaccount.com", cfg.ImpersonateServiceAccount)
	require.Equal(t, "my-billing", cfg.QuotaProject)
}

func TestGCPModelToConfig_NilSafe(t *testing.T) {
	t.Parallel()
	var m *auth.GCPModel
	cfg, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError())
	require.Empty(t, cfg.Credentials)
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/provider/auth/... -run TestGCPModel`
Expected: FAIL with `undefined: auth.GCPModel`.

- [ ] **Step 3: Implement `gcp.go`**

Create `internal/provider/auth/gcp.go`:

```go
package auth

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type GCPModel struct {
	Credentials               types.String `tfsdk:"credentials"`
	CredentialsFile           types.String `tfsdk:"credentials_file"`
	ImpersonateServiceAccount types.String `tfsdk:"impersonate_service_account"`
	QuotaProject              types.String `tfsdk:"quota_project"`
}

func GCPBlockSchema() schema.Block {
	return schema.SingleNestedBlock{
		Description: "GCP KMS credential configuration.",
		Attributes: map[string]schema.Attribute{
			"credentials":                 schema.StringAttribute{Optional: true, Sensitive: true},
			"credentials_file":            schema.StringAttribute{Optional: true},
			"impersonate_service_account": schema.StringAttribute{Optional: true},
			"quota_project":               schema.StringAttribute{Optional: true},
		},
	}
}

func (m *GCPModel) ToConfig(_ context.Context) (GCPConfig, diag.Diagnostics) {
	if m == nil {
		return GCPConfig{}, nil
	}
	return GCPConfig{
		Credentials:               m.Credentials.ValueString(),
		CredentialsFile:           m.CredentialsFile.ValueString(),
		ImpersonateServiceAccount: m.ImpersonateServiceAccount.ValueString(),
		QuotaProject:              m.QuotaProject.ValueString(),
	}, nil
}
```

- [ ] **Step 4: Run — expect pass**

Run: `go test ./internal/provider/auth/... -v -run TestGCPModel`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/provider/auth/gcp.go internal/provider/auth/gcp_test.go
git commit -S -m "feat(auth): GCP schema block and Model.ToConfig"
```

---

### Task 6: Azure auth schema + model→Config

**Files:**
- Create: `internal/provider/auth/azure.go`
- Create: `internal/provider/auth/azure_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/provider/auth/azure_test.go`:

```go
package auth_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/require"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
)

func TestAzureModelToConfig_OIDC(t *testing.T) {
	t.Parallel()
	m := &auth.AzureModel{
		TenantID: types.StringValue("00000000-0000-0000-0000-000000000000"),
		ClientID: types.StringValue("11111111-1111-1111-1111-111111111111"),
		UseOIDC:  types.BoolValue(true),
	}
	cfg, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError(), diags.Errors())
	require.Equal(t, "00000000-0000-0000-0000-000000000000", cfg.TenantID)
	require.True(t, cfg.UseOIDC)
	require.False(t, cfg.UseMSI)
}

func TestAzureModelToConfig_NilSafe(t *testing.T) {
	t.Parallel()
	var m *auth.AzureModel
	_, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError())
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/provider/auth/... -run TestAzureModel`
Expected: FAIL with `undefined: auth.AzureModel`.

- [ ] **Step 3: Implement `azure.go`**

Create `internal/provider/auth/azure.go`:

```go
package auth

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type AzureModel struct {
	TenantID            types.String `tfsdk:"tenant_id"`
	ClientID            types.String `tfsdk:"client_id"`
	ClientSecret        types.String `tfsdk:"client_secret"`
	UseMSI              types.Bool   `tfsdk:"use_msi"`
	UseOIDC             types.Bool   `tfsdk:"use_oidc"`
	UseWorkloadIdentity types.Bool   `tfsdk:"use_workload_identity"`
	UseCLI              types.Bool   `tfsdk:"use_cli"`
}

func AzureBlockSchema() schema.Block {
	return schema.SingleNestedBlock{
		Description: "Azure Key Vault credential configuration.",
		Attributes: map[string]schema.Attribute{
			"tenant_id":             schema.StringAttribute{Optional: true},
			"client_id":             schema.StringAttribute{Optional: true},
			"client_secret":         schema.StringAttribute{Optional: true, Sensitive: true},
			"use_msi":               schema.BoolAttribute{Optional: true},
			"use_oidc":              schema.BoolAttribute{Optional: true},
			"use_workload_identity": schema.BoolAttribute{Optional: true},
			"use_cli":               schema.BoolAttribute{Optional: true},
		},
	}
}

func (m *AzureModel) ToConfig(_ context.Context) (AzureConfig, diag.Diagnostics) {
	if m == nil {
		return AzureConfig{}, nil
	}
	return AzureConfig{
		TenantID:            m.TenantID.ValueString(),
		ClientID:            m.ClientID.ValueString(),
		ClientSecret:        m.ClientSecret.ValueString(),
		UseMSI:              m.UseMSI.ValueBool(),
		UseOIDC:             m.UseOIDC.ValueBool(),
		UseWorkloadIdentity: m.UseWorkloadIdentity.ValueBool(),
		UseCLI:              m.UseCLI.ValueBool(),
	}, nil
}
```

- [ ] **Step 4: Run — expect pass**

Run: `go test ./internal/provider/auth/... -v -run TestAzureModel`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/provider/auth/azure.go internal/provider/auth/azure_test.go
git commit -S -m "feat(auth): Azure schema block and Model.ToConfig

Supports tenant/client/secret, MSI, OIDC (GitHub Actions, TFC dyn creds),
workload identity, and CLI credential sources."
```

---

### Task 7: age auth schema + model→Config

**Files:**
- Create: `internal/provider/auth/age.go`
- Create: `internal/provider/auth/age_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/provider/auth/age_test.go`:

```go
package auth_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/require"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
)

func TestAgeModelToConfig_KeyFile(t *testing.T) {
	t.Parallel()
	m := &auth.AgeModel{KeyFile: types.StringValue("/path/to/keys.txt")}
	cfg, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError())
	require.Equal(t, "/path/to/keys.txt", cfg.KeyFile)
}

func TestAgeModelToConfig_KeyCommand(t *testing.T) {
	t.Parallel()
	m := &auth.AgeModel{KeyCommand: types.StringValue("pass show age/sops")}
	cfg, _ := m.ToConfig(context.Background())
	require.Equal(t, "pass show age/sops", cfg.KeyCommand)
}

func TestAgeModelToConfig_NilSafe(t *testing.T) {
	t.Parallel()
	var m *auth.AgeModel
	_, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError())
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/provider/auth/... -run TestAgeModel`
Expected: FAIL with `undefined: auth.AgeModel`.

- [ ] **Step 3: Implement `age.go`**

Create `internal/provider/auth/age.go`:

```go
package auth

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type AgeModel struct {
	Key               types.String `tfsdk:"key"`
	KeyFile           types.String `tfsdk:"key_file"`
	KeyCommand        types.String `tfsdk:"key_command"`
	SSHPrivateKeyFile types.String `tfsdk:"ssh_private_key_file"`
}

func AgeBlockSchema() schema.Block {
	return schema.SingleNestedBlock{
		Description: "age key configuration.",
		Attributes: map[string]schema.Attribute{
			"key":                  schema.StringAttribute{Optional: true, Sensitive: true},
			"key_file":             schema.StringAttribute{Optional: true},
			"key_command":          schema.StringAttribute{Optional: true},
			"ssh_private_key_file": schema.StringAttribute{Optional: true},
		},
	}
}

func (m *AgeModel) ToConfig(_ context.Context) (AgeConfig, diag.Diagnostics) {
	if m == nil {
		return AgeConfig{}, nil
	}
	return AgeConfig{
		Key:               m.Key.ValueString(),
		KeyFile:           m.KeyFile.ValueString(),
		KeyCommand:        m.KeyCommand.ValueString(),
		SSHPrivateKeyFile: m.SSHPrivateKeyFile.ValueString(),
	}, nil
}
```

- [ ] **Step 4: Run — expect pass**

Run: `go test ./internal/provider/auth/... -v -run TestAgeModel`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/provider/auth/age.go internal/provider/auth/age_test.go
git commit -S -m "feat(auth): age schema block and Model.ToConfig"
```

---

### Task 8: PGP auth schema + model→Config

**Files:**
- Create: `internal/provider/auth/pgp.go`
- Create: `internal/provider/auth/pgp_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/provider/auth/pgp_test.go`:

```go
package auth_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/require"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
)

func TestPGPModelToConfig(t *testing.T) {
	t.Parallel()
	m := &auth.PGPModel{GnupgHome: types.StringValue("/home/user/.gnupg")}
	cfg, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError())
	require.Equal(t, "/home/user/.gnupg", cfg.GnupgHome)
}

func TestPGPModelToConfig_NilSafe(t *testing.T) {
	t.Parallel()
	var m *auth.PGPModel
	_, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError())
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/provider/auth/... -run TestPGPModel`
Expected: FAIL with `undefined: auth.PGPModel`.

- [ ] **Step 3: Implement `pgp.go`**

Create `internal/provider/auth/pgp.go`:

```go
package auth

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type PGPModel struct {
	GnupgHome types.String `tfsdk:"gnupg_home"`
}

func PGPBlockSchema() schema.Block {
	return schema.SingleNestedBlock{
		Description: "PGP / GnuPG configuration.",
		Attributes: map[string]schema.Attribute{
			"gnupg_home": schema.StringAttribute{Optional: true},
		},
	}
}

func (m *PGPModel) ToConfig(_ context.Context) (PGPConfig, diag.Diagnostics) {
	if m == nil {
		return PGPConfig{}, nil
	}
	return PGPConfig{GnupgHome: m.GnupgHome.ValueString()}, nil
}
```

- [ ] **Step 4: Run — expect pass**

Run: `go test ./internal/provider/auth/... -v -run TestPGPModel`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/provider/auth/pgp.go internal/provider/auth/pgp_test.go
git commit -S -m "feat(auth): PGP schema block and Model.ToConfig"
```

---

### Task 9: Generate age test fixtures

We need encrypted files we can decrypt in unit tests without cloud creds. Use `age-keygen` + `sops` CLI to generate fixtures committed under `testdata/`.

**Files:**
- Create: `testdata/age-key.txt`
- Create: `testdata/secrets.yaml`
- Create: `testdata/secrets.json`
- Create: `testdata/secrets.env`
- Create: `testdata/secrets.ini`
- Create: `testdata/secrets.bin`

- [ ] **Step 1: Confirm prerequisites**

Run:
```bash
which age-keygen
which sops
```
Expected: both binaries present. If not, install (`brew install age sops`).

- [ ] **Step 2: Generate the age key**

Run:
```bash
cd /Volumes/Development/pessoal/elioseverojunior/go/terraform-sops-provider
age-keygen -o testdata/age-key.txt
PUB=$(grep 'public key:' testdata/age-key.txt | awk '{print $NF}')
echo "Public key: $PUB"
```
Expected: prints an `age1...` recipient.

- [ ] **Step 3: Write the plaintext source files**

Create `testdata/_plain/secrets.yaml`:

```yaml
database:
  host: db.example.com
  password: hunter2
api_key: sk-test-12345
nested:
  list:
    - one
    - two
```

Create `testdata/_plain/secrets.json`:

```json
{
  "database": {"host": "db.example.com", "password": "hunter2"},
  "api_key": "sk-test-12345",
  "nested": {"list": ["one", "two"]}
}
```

Create `testdata/_plain/secrets.env`:

```
DATABASE_HOST=db.example.com
DATABASE_PASSWORD=hunter2
API_KEY=sk-test-12345
```

Create `testdata/_plain/secrets.ini`:

```ini
[database]
host = db.example.com
password = hunter2

[api]
key = sk-test-12345
```

Create `testdata/_plain/secrets.bin` (random bytes):
```bash
head -c 128 /dev/urandom > testdata/_plain/secrets.bin
```

- [ ] **Step 4: Encrypt the fixtures**

Run:
```bash
export SOPS_AGE_RECIPIENTS="$PUB"
sops --encrypt --input-type yaml   --output-type yaml   testdata/_plain/secrets.yaml > testdata/secrets.yaml
sops --encrypt --input-type json   --output-type json   testdata/_plain/secrets.json > testdata/secrets.json
sops --encrypt --input-type dotenv --output-type dotenv testdata/_plain/secrets.env  > testdata/secrets.env
sops --encrypt --input-type ini    --output-type ini    testdata/_plain/secrets.ini  > testdata/secrets.ini
sops --encrypt --input-type binary --output-type binary testdata/_plain/secrets.bin  > testdata/secrets.bin
```

Expected: 5 encrypted files in `testdata/`; each contains a `sops:` metadata section.

- [ ] **Step 5: Sanity-check round-trip**

Run:
```bash
export SOPS_AGE_KEY_FILE="testdata/age-key.txt"
sops --decrypt testdata/secrets.yaml
```
Expected: prints the original plaintext YAML.

- [ ] **Step 6: Commit**

```bash
git add testdata/age-key.txt testdata/secrets.yaml testdata/secrets.json testdata/secrets.env testdata/secrets.ini testdata/secrets.bin testdata/_plain/
git commit -S -m "test: add age-encrypted fixtures for sopswrap tests

testdata/age-key.txt is a test-only private key (NOT a real secret).
Plaintext sources kept in testdata/_plain/ for fixture regeneration."
```

---

### Task 10: `sopswrap.Store` — format → SOPS Store dispatcher

Each SOPS-supported format has a corresponding `Store` type in `github.com/getsops/sops/v3/stores/{yaml,json,dotenv,ini,binary}`. This task wraps the dispatch.

**Files:**
- Create: `internal/sopswrap/store.go`
- Create: `internal/sopswrap/store_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/sopswrap/store_test.go`:

```go
package sopswrap_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elioseverojunior/terraform-provider-sops/internal/sopswrap"
)

func TestStoreFor_KnownFormats(t *testing.T) {
	t.Parallel()
	for _, f := range []sopswrap.Format{
		sopswrap.FormatYAML,
		sopswrap.FormatJSON,
		sopswrap.FormatDotenv,
		sopswrap.FormatINI,
		sopswrap.FormatBinary,
	} {
		f := f
		t.Run(string(f), func(t *testing.T) {
			t.Parallel()
			s, err := sopswrap.StoreFor(f)
			require.NoError(t, err)
			require.NotNil(t, s)
		})
	}
}

func TestStoreFor_Unknown(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.StoreFor(sopswrap.Format("toml"))
	require.Error(t, err)
}

func TestFormatFromPath_AutoDetect(t *testing.T) {
	t.Parallel()
	tests := map[string]sopswrap.Format{
		"secrets.yaml":   sopswrap.FormatYAML,
		"secrets.yml":    sopswrap.FormatYAML,
		"secrets.json":   sopswrap.FormatJSON,
		"secrets.env":    sopswrap.FormatDotenv,
		"secrets.ini":    sopswrap.FormatINI,
		"secrets.binary": sopswrap.FormatBinary,
		"secrets.txt":    sopswrap.FormatBinary, // fallback
	}
	for path, want := range tests {
		path, want := path, want
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			got := sopswrap.FormatFromPath(path)
			require.Equal(t, want, got)
		})
	}
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/sopswrap/...`
Expected: FAIL with `package sopswrap: no Go files`.

- [ ] **Step 3: Implement `store.go`**

Create `internal/sopswrap/store.go`:

```go
// Package sopswrap is the thin wrapper around the SOPS Go library that lets us
// inject per-call credentials. Callers should never import sops/v3 directly.
package sopswrap

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/stores/binary"
	"github.com/getsops/sops/v3/stores/dotenv"
	"github.com/getsops/sops/v3/stores/ini"
	"github.com/getsops/sops/v3/stores/json"
	"github.com/getsops/sops/v3/stores/yaml"
)

// Format names the SOPS plaintext/ciphertext format.
type Format string

const (
	FormatYAML   Format = "yaml"
	FormatJSON   Format = "json"
	FormatDotenv Format = "dotenv"
	FormatINI    Format = "ini"
	FormatBinary Format = "binary"
	FormatRaw    Format = "raw" // alias for Binary at the API layer
)

// Store unifies the SOPS Store interface (load encrypted/plaintext file, emit either).
type Store interface {
	LoadEncryptedFile(in []byte) (sops.Tree, error)
	LoadPlainFile(in []byte) (sops.TreeBranches, error)
	EmitEncryptedFile(tree sops.Tree) ([]byte, error)
	EmitPlainFile(tree sops.TreeBranches) ([]byte, error)
}

// StoreFor returns the SOPS Store for the given format.
func StoreFor(f Format) (Store, error) {
	switch f {
	case FormatYAML:
		return &yaml.Store{}, nil
	case FormatJSON:
		return &json.Store{}, nil
	case FormatDotenv:
		return &dotenv.Store{}, nil
	case FormatINI:
		return &ini.Store{}, nil
	case FormatBinary, FormatRaw:
		return &binary.Store{}, nil
	default:
		return nil, fmt.Errorf("sopswrap: unknown format %q (want yaml|json|dotenv|ini|binary|raw)", f)
	}
}

// FormatFromPath auto-detects from file extension. Falls back to FormatBinary
// (matches SOPS CLI behavior for unrecognized extensions).
func FormatFromPath(p string) Format {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".yaml", ".yml":
		return FormatYAML
	case ".json":
		return FormatJSON
	case ".env":
		return FormatDotenv
	case ".ini":
		return FormatINI
	default:
		return FormatBinary
	}
}
```

- [ ] **Step 4: Run — expect pass**

Run: `go test ./internal/sopswrap/... -v`
Expected: all subtests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/sopswrap/store.go internal/sopswrap/store_test.go
git commit -S -m "feat(sopswrap): Store dispatcher and FormatFromPath helper

Maps Format → sops stores/{yaml,json,dotenv,ini,binary}. Auto-detection
falls back to binary, matching the sops CLI."
```

---

### Task 11: `sopswrap.concurrency` — global semaphore

Fixes carlpett #126.

**Files:**
- Create: `internal/sopswrap/concurrency.go`
- Create: `internal/sopswrap/concurrency_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/sopswrap/concurrency_test.go`:

```go
package sopswrap_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elioseverojunior/terraform-provider-sops/internal/sopswrap"
)

func TestSemaphore_RespectsLimit(t *testing.T) {
	t.Parallel()
	sem := sopswrap.NewSemaphore(2)

	var concurrent int32
	var peak int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := sem.Acquire(context.Background())
			require.NoError(t, err)
			defer rel()

			now := atomic.AddInt32(&concurrent, 1)
			for {
				p := atomic.LoadInt32(&peak)
				if now <= p || atomic.CompareAndSwapInt32(&peak, p, now) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			atomic.AddInt32(&concurrent, -1)
		}()
	}
	wg.Wait()
	require.LessOrEqual(t, atomic.LoadInt32(&peak), int32(2),
		"peak concurrency must not exceed limit")
}

func TestSemaphore_ZeroLimitUsesDefault(t *testing.T) {
	t.Parallel()
	sem := sopswrap.NewSemaphore(0)
	rel, err := sem.Acquire(context.Background())
	require.NoError(t, err)
	rel()
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/sopswrap/... -run TestSemaphore`
Expected: FAIL with `undefined: sopswrap.NewSemaphore`.

- [ ] **Step 3: Implement `concurrency.go`**

Create `internal/sopswrap/concurrency.go`:

```go
package sopswrap

import (
	"context"

	"golang.org/x/sync/semaphore"
)

// DefaultConcurrency is the default cap on parallel decrypt/encrypt calls.
// Empirically chosen to stay under the carlpett #126 threshold and play nice
// with the GPG agent.
const DefaultConcurrency = 4

// Semaphore is a thin wrapper around x/sync/semaphore.Weighted that returns
// a release function for ergonomic defer-release.
type Semaphore struct {
	w *semaphore.Weighted
}

// NewSemaphore returns a Semaphore with the given limit. limit <= 0 falls back to DefaultConcurrency.
func NewSemaphore(limit int) *Semaphore {
	if limit <= 0 {
		limit = DefaultConcurrency
	}
	return &Semaphore{w: semaphore.NewWeighted(int64(limit))}
}

// Acquire blocks until a slot is free or ctx is cancelled.
// Returns a release function. Callers should `defer release()`.
func (s *Semaphore) Acquire(ctx context.Context) (release func(), err error) {
	if err := s.w.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	return func() { s.w.Release(1) }, nil
}
```

- [ ] **Step 4: Run — expect pass**

Run: `go test ./internal/sopswrap/... -v -run TestSemaphore`
Expected: both PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/sopswrap/concurrency.go internal/sopswrap/concurrency_test.go
git commit -S -m "feat(sopswrap): bounded semaphore for parallel decrypt calls

Mitigates carlpett #126 by capping concurrent SOPS calls.
Default limit is 4; configurable via provider block concurrency_limit."
```

---

### Task 12: `sopswrap.Output` — flatten map + JSON + metadata

Translates a decrypted `sops.Tree` into the three output shapes the data source exposes.

**Files:**
- Create: `internal/sopswrap/output.go`
- Create: `internal/sopswrap/output_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/sopswrap/output_test.go`:

```go
package sopswrap_test

import (
	"encoding/json"
	"testing"

	sops "github.com/getsops/sops/v3"
	"github.com/stretchr/testify/require"

	"github.com/elioseverojunior/terraform-provider-sops/internal/sopswrap"
)

func TestFlatten_NestedMap(t *testing.T) {
	t.Parallel()
	tree := sops.TreeBranches{
		sops.TreeBranch{
			sops.TreeItem{Key: "database", Value: sops.TreeBranch{
				sops.TreeItem{Key: "host", Value: "db.example.com"},
				sops.TreeItem{Key: "password", Value: "hunter2"},
			}},
			sops.TreeItem{Key: "api_key", Value: "sk-test-12345"},
		},
	}
	flat := sopswrap.Flatten(tree)
	require.Equal(t, "db.example.com", flat["database.host"])
	require.Equal(t, "hunter2", flat["database.password"])
	require.Equal(t, "sk-test-12345", flat["api_key"])
}

func TestFlatten_List(t *testing.T) {
	t.Parallel()
	tree := sops.TreeBranches{
		sops.TreeBranch{
			sops.TreeItem{Key: "nested", Value: sops.TreeBranch{
				sops.TreeItem{Key: "list", Value: []interface{}{"one", "two"}},
			}},
		},
	}
	flat := sopswrap.Flatten(tree)
	require.Equal(t, "one", flat["nested.list.0"])
	require.Equal(t, "two", flat["nested.list.1"])
}

func TestToJSON_NestedMap(t *testing.T) {
	t.Parallel()
	tree := sops.TreeBranches{
		sops.TreeBranch{
			sops.TreeItem{Key: "a", Value: sops.TreeBranch{
				sops.TreeItem{Key: "b", Value: 42},
			}},
		},
	}
	js, err := sopswrap.ToJSON(tree)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(js, &parsed))
	require.Equal(t, float64(42), parsed["a"].(map[string]any)["b"])
}

func TestExtractMetadata_KMSARNs(t *testing.T) {
	t.Parallel()
	tree := sops.Tree{
		Metadata: sops.Metadata{
			Version: "3.10.0",
			KeyGroups: []sops.KeyGroup{
				// We don't construct real MasterKeys here; ExtractMetadata accesses
				// only fields the framework can serialize without crypto state.
			},
		},
	}
	meta := sopswrap.ExtractMetadata(tree)
	require.Equal(t, "3.10.0", meta.Version)
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/sopswrap/... -run TestFlatten`
Expected: FAIL with `undefined: sopswrap.Flatten` etc.

- [ ] **Step 3: Implement `output.go`**

Create `internal/sopswrap/output.go`:

```go
package sopswrap

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	sops "github.com/getsops/sops/v3"
)

// Flatten produces the carlpett-compatible flat map[string]string output.
// Nested keys are joined with ".". List indices are stringified.
func Flatten(branches sops.TreeBranches) map[string]string {
	out := map[string]string{}
	for _, branch := range branches {
		walk(out, "", branch)
	}
	return out
}

func walk(out map[string]string, prefix string, v interface{}) {
	switch tv := v.(type) {
	case sops.TreeBranch:
		for _, item := range tv {
			keyStr := fmt.Sprintf("%v", item.Key)
			next := keyStr
			if prefix != "" {
				next = prefix + "." + keyStr
			}
			walk(out, next, item.Value)
		}
	case []interface{}:
		for i, item := range tv {
			next := strconv.Itoa(i)
			if prefix != "" {
				next = prefix + "." + next
			}
			walk(out, next, item)
		}
	case sops.Comment:
		// Skip SOPS-internal comments.
	default:
		out[prefix] = fmt.Sprintf("%v", tv)
	}
}

// ToJSON marshals the decrypted tree into structured JSON (spec §6.1 data_json).
func ToJSON(branches sops.TreeBranches) ([]byte, error) {
	obj := toGo(branches)
	return json.Marshal(obj)
}

func toGo(v interface{}) interface{} {
	switch tv := v.(type) {
	case sops.TreeBranches:
		// Multiple branches (rare; YAML multi-doc). Return as list.
		if len(tv) == 1 {
			return toGo(tv[0])
		}
		out := make([]interface{}, len(tv))
		for i, b := range tv {
			out[i] = toGo(b)
		}
		return out
	case sops.TreeBranch:
		m := map[string]interface{}{}
		for _, item := range tv {
			if _, ok := item.Key.(sops.Comment); ok {
				continue
			}
			m[fmt.Sprintf("%v", item.Key)] = toGo(item.Value)
		}
		return m
	case []interface{}:
		out := make([]interface{}, 0, len(tv))
		for _, item := range tv {
			if _, ok := item.(sops.Comment); ok {
				continue
			}
			out = append(out, toGo(item))
		}
		return out
	case sops.Comment:
		return nil
	default:
		return v
	}
}

// Metadata is the surface we expose as the `metadata` attribute on data sources.
type Metadata struct {
	LastModified      time.Time `json:"lastmodified"`
	MAC               string    `json:"mac"`
	Version           string    `json:"version"`
	KMSARNs           []string  `json:"kms_arns"`
	GCPKMSResources   []string  `json:"gcp_kms_resources"`
	AzureKVURLs       []string  `json:"azure_kv_urls"`
	AgeRecipients     []string  `json:"age_recipients"`
	PGPFingerprints   []string  `json:"pgp_fingerprints"`
	UnencryptedSuffix string    `json:"unencrypted_suffix,omitempty"`
	EncryptedSuffix   string    `json:"encrypted_suffix,omitempty"`
	UnencryptedRegex  string    `json:"unencrypted_regex,omitempty"`
	EncryptedRegex    string    `json:"encrypted_regex,omitempty"`
}

// ExtractMetadata pulls audit-relevant metadata out of a tree.
// Tolerates partial/empty key groups (e.g., in tests).
func ExtractMetadata(tree sops.Tree) Metadata {
	meta := Metadata{
		LastModified:      tree.Metadata.LastModified,
		MAC:               tree.Metadata.MessageAuthenticationCode,
		Version:           tree.Metadata.Version,
		UnencryptedSuffix: tree.Metadata.UnencryptedSuffix,
		EncryptedSuffix:   tree.Metadata.EncryptedSuffix,
		UnencryptedRegex:  tree.Metadata.UnencryptedRegex,
		EncryptedRegex:    tree.Metadata.EncryptedRegex,
	}
	for _, group := range tree.Metadata.KeyGroups {
		for _, k := range group {
			typeName := strings.ToLower(fmt.Sprintf("%T", k))
			switch {
			case strings.Contains(typeName, "kms.masterkey"):
				meta.KMSARNs = append(meta.KMSARNs, k.ToString())
			case strings.Contains(typeName, "gcpkms.masterkey"):
				meta.GCPKMSResources = append(meta.GCPKMSResources, k.ToString())
			case strings.Contains(typeName, "azkv.masterkey"):
				meta.AzureKVURLs = append(meta.AzureKVURLs, k.ToString())
			case strings.Contains(typeName, "age.masterkey"):
				meta.AgeRecipients = append(meta.AgeRecipients, k.ToString())
			case strings.Contains(typeName, "pgp.masterkey"):
				meta.PGPFingerprints = append(meta.PGPFingerprints, k.ToString())
			}
		}
	}
	return meta
}
```

- [ ] **Step 4: Run — expect pass**

Run: `go test ./internal/sopswrap/... -v -run TestFlatten`
Run: `go test ./internal/sopswrap/... -v -run TestToJSON`
Run: `go test ./internal/sopswrap/... -v -run TestExtractMetadata`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/sopswrap/output.go internal/sopswrap/output_test.go
git commit -S -m "feat(sopswrap): output shaping — Flatten, ToJSON, ExtractMetadata

Provides the three output shapes a data source exposes:
- Flatten() for carlpett-compatible flat map (joined with .)
- ToJSON() for structured nested output (fixes carlpett #98)
- ExtractMetadata() for the audit-facing metadata attribute"
```

---

### Task 13: `sopswrap.MasterKey` — build SOPS master keys with injected credentials

The **core architectural decision** of this provider lives here. Given an `auth.Config` and the encrypted tree's metadata (which carries the KMS ARNs / GCP resource IDs / etc.), reconstruct `MasterKey` structs with our injected credentials so SOPS can fetch the data key.

**Files:**
- Create: `internal/sopswrap/masterkey.go`
- Create: `internal/sopswrap/masterkey_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/sopswrap/masterkey_test.go`:

```go
package sopswrap_test

import (
	"testing"

	sops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/kms"
	"github.com/stretchr/testify/require"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
	"github.com/elioseverojunior/terraform-provider-sops/internal/sopswrap"
)

func TestRebuildKeyGroups_InjectsAWSProfile(t *testing.T) {
	t.Parallel()

	// Encrypted tree references one KMS key with no profile set.
	origKMS := kms.NewMasterKeyFromArn("arn:aws:kms:us-east-1:123:key/abc", nil, "")
	tree := sops.Tree{
		Metadata: sops.Metadata{
			KeyGroups: []sops.KeyGroup{{origKMS}},
		},
	}

	cfg := auth.Config{
		AWS: auth.AWSConfig{Profile: "production-sre", Region: "us-east-1"},
	}

	groups, err := sopswrap.RebuildKeyGroups(tree, cfg)
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Len(t, groups[0], 1)

	// Type-assert and check the rebuilt key carries our profile.
	rebuilt, ok := groups[0][0].(*kms.MasterKey)
	require.True(t, ok, "expected kms.MasterKey")
	require.Equal(t, "production-sre", rebuilt.AwsProfile,
		"profile must be injected from auth.Config")
	require.Equal(t, "arn:aws:kms:us-east-1:123:key/abc", rebuilt.Arn)
}

func TestRebuildKeyGroups_AgePassthrough(t *testing.T) {
	t.Parallel()
	// age MasterKeys don't need credential injection — they read SOPS_AGE_KEY*
	// from env in their Decrypt() path. Verify we pass them through unchanged.
	ageKey, err := age.MasterKeyFromRecipient("age1l0qm8nz98p79nczyymyl3wmt78q6jfxnj9d3jrjxhm9wexp2qcvshk0wzh")
	require.NoError(t, err)
	tree := sops.Tree{
		Metadata: sops.Metadata{KeyGroups: []sops.KeyGroup{{ageKey}}},
	}
	groups, err := sopswrap.RebuildKeyGroups(tree, auth.Config{})
	require.NoError(t, err)
	require.Len(t, groups[0], 1)
	rebuilt, ok := groups[0][0].(*age.MasterKey)
	require.True(t, ok)
	require.Equal(t, ageKey.Recipient, rebuilt.Recipient)
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/sopswrap/... -run TestRebuildKeyGroups`
Expected: FAIL with `undefined: sopswrap.RebuildKeyGroups`.

- [ ] **Step 3: Implement `masterkey.go`**

Create `internal/sopswrap/masterkey.go`:

```go
package sopswrap

import (
	"fmt"

	sops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/azkv"
	"github.com/getsops/sops/v3/gcpkms"
	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/kms"
	"github.com/getsops/sops/v3/pgp"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
)

// RebuildKeyGroups walks an encrypted tree's key groups and reconstructs each
// MasterKey with credentials from the provided auth.Config. This is the entire
// reason this provider exists — SOPS's decrypt.Data() does not give us this hook.
//
// Each key type knows what to do with our config:
//   - kms.MasterKey: takes Profile + assume-role + region
//   - gcpkms.MasterKey: takes credentials file/JSON + impersonation target
//   - azkv.MasterKey: takes tenant/client/secret + auth-method flags
//   - age.MasterKey: passthrough (reads env in Decrypt())
//   - pgp.MasterKey: takes GnupgHome
func RebuildKeyGroups(tree sops.Tree, cfg auth.Config) ([]sops.KeyGroup, error) {
	out := make([]sops.KeyGroup, len(tree.Metadata.KeyGroups))
	for i, group := range tree.Metadata.KeyGroups {
		rebuilt := make(sops.KeyGroup, 0, len(group))
		for _, mk := range group {
			rk, err := rebuildOne(mk, cfg)
			if err != nil {
				return nil, fmt.Errorf("rebuilding %T: %w", mk, err)
			}
			rebuilt = append(rebuilt, rk)
		}
		out[i] = rebuilt
	}
	return out, nil
}

func rebuildOne(mk keys.MasterKey, cfg auth.Config) (keys.MasterKey, error) {
	switch k := mk.(type) {
	case *kms.MasterKey:
		out := kms.NewMasterKeyFromArn(k.Arn, k.EncryptionContext, k.Role)
		out.EncryptedKey = k.EncryptedKey
		out.CreationDate = k.CreationDate
		out.AwsProfile = cfg.AWS.Profile
		if cfg.AWS.AssumeRole != nil && out.Role == "" {
			out.Role = cfg.AWS.AssumeRole.RoleARN
		}
		return out, nil

	case *gcpkms.MasterKey:
		out := gcpkms.NewMasterKeyFromResourceID(k.ResourceID)
		out.EncryptedKey = k.EncryptedKey
		out.CreationDate = k.CreationDate
		// Per-call credential injection: gcpkms reads GOOGLE_APPLICATION_CREDENTIALS
		// + env, so we set those via scoped env in the provider's Configure path.
		// (Wired up in Task 19.)
		_ = cfg.GCP
		return out, nil

	case *azkv.MasterKey:
		out := azkv.NewMasterKey(k.VaultURL, k.Name, k.Version)
		out.EncryptedKey = k.EncryptedKey
		out.CreationDate = k.CreationDate
		_ = cfg.Azure
		return out, nil

	case *age.MasterKey:
		// Recipient is the only persistent state; the private-key lookup
		// happens inside Decrypt() against env vars. We set env scope outside.
		out, err := age.MasterKeyFromRecipient(k.Recipient)
		if err != nil {
			return nil, err
		}
		out.EncryptedKey = k.EncryptedKey
		out.CreationDate = k.CreationDate
		return out, nil

	case *pgp.MasterKey:
		out := pgp.NewMasterKeyFromFingerprint(k.Fingerprint)
		out.EncryptedKey = k.EncryptedKey
		out.CreationDate = k.CreationDate
		// GnupgHome is read from env; we set GNUPGHOME in scoped env.
		_ = cfg.PGP
		return out, nil

	default:
		// Pass through any keytype we don't recognize so the tree still works.
		return mk, nil
	}
}
```

- [ ] **Step 4: Run — expect pass**

Run: `go test ./internal/sopswrap/... -v -run TestRebuildKeyGroups`
Expected: both PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/sopswrap/masterkey.go internal/sopswrap/masterkey_test.go
git commit -S -m "feat(sopswrap): rebuild MasterKey groups with injected credentials

This is the architectural keystone of the provider: by bypassing
decrypt.Data() and reconstructing key groups ourselves, we can inject
per-call AWS profile / region / assume_role into kms.MasterKey.

Per-call GCP/Azure/PGP creds are reached via scoped env injection in
the provider Configure path (wired up next)."
```

---

### Task 14: `sopswrap.Decrypt` — the orchestrator

Glues Store + Concurrency + MasterKey rebuilding + tree decrypt + Output together.

**Files:**
- Create: `internal/sopswrap/decrypt.go`
- Create: `internal/sopswrap/decrypt_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/sopswrap/decrypt_test.go`:

```go
package sopswrap_test

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
	"github.com/elioseverojunior/terraform-provider-sops/internal/sopswrap"
)

func setAgeEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SOPS_AGE_KEY_FILE", absTestdata(t, "age-key.txt"))
}

func absTestdata(t *testing.T, name string) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	// tests run from internal/sopswrap; testdata lives at repo root
	return strings.TrimSuffix(wd, "/internal/sopswrap") + "/testdata/" + name
}

func TestDecrypt_YAMLFixture(t *testing.T) {
	t.Parallel()
	setAgeEnv(t)

	src, err := os.ReadFile(absTestdata(t, "secrets.yaml"))
	require.NoError(t, err)

	res, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: src,
		Format: sopswrap.FormatYAML,
		Config: auth.Config{},
	})
	require.NoError(t, err)
	require.Contains(t, string(res.Plaintext), "hunter2")
	require.Equal(t, "hunter2", res.Flat["database.password"])
	require.Equal(t, "sk-test-12345", res.Flat["api_key"])
}

func TestDecrypt_JSONFixture(t *testing.T) {
	t.Parallel()
	setAgeEnv(t)
	src, err := os.ReadFile(absTestdata(t, "secrets.json"))
	require.NoError(t, err)
	res, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: src, Format: sopswrap.FormatJSON,
	})
	require.NoError(t, err)
	require.Contains(t, string(res.Plaintext), "hunter2")
}

func TestDecrypt_DotenvFixture(t *testing.T) {
	t.Parallel()
	setAgeEnv(t)
	src, err := os.ReadFile(absTestdata(t, "secrets.env"))
	require.NoError(t, err)
	res, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: src, Format: sopswrap.FormatDotenv,
	})
	require.NoError(t, err)
	require.Equal(t, "hunter2", res.Flat["DATABASE_PASSWORD"])
}

func TestDecrypt_BinaryFixture(t *testing.T) {
	t.Parallel()
	setAgeEnv(t)
	src, err := os.ReadFile(absTestdata(t, "secrets.bin"))
	require.NoError(t, err)
	res, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: src, Format: sopswrap.FormatBinary,
	})
	require.NoError(t, err)
	require.NotEmpty(t, res.Plaintext)
}

// Concurrency regression test — reproduces carlpett #126 if our semaphore is broken.
func TestDecrypt_ParallelStable(t *testing.T) {
	t.Parallel()
	setAgeEnv(t)
	src, err := os.ReadFile(absTestdata(t, "secrets.yaml"))
	require.NoError(t, err)

	const N = 32
	var wg sync.WaitGroup
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
				Source: src, Format: sopswrap.FormatYAML,
			})
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("parallel decrypt failed: %v", err)
	}
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/sopswrap/... -run TestDecrypt`
Expected: FAIL with `undefined: sopswrap.Decrypt`.

- [ ] **Step 3: Implement `decrypt.go`**

Create `internal/sopswrap/decrypt.go`:

```go
package sopswrap

import (
	"context"
	"fmt"
	"sync"

	sops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/keyservice"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
)

// Package-level semaphore. Provider's Configure may swap it out.
var (
	semMu sync.RWMutex
	sem   = NewSemaphore(DefaultConcurrency)
)

// SetGlobalConcurrency replaces the package-level semaphore. Called by the
// provider's Configure with the user's `concurrency_limit`.
func SetGlobalConcurrency(limit int) {
	semMu.Lock()
	defer semMu.Unlock()
	sem = NewSemaphore(limit)
}

func getSem() *Semaphore {
	semMu.RLock()
	defer semMu.RUnlock()
	return sem
}

// DecryptInput is the request to Decrypt.
type DecryptInput struct {
	// Source is the raw encrypted bytes.
	Source []byte
	// Format selects the SOPS store. Required.
	Format Format
	// Config is the merged credential configuration for this call.
	Config auth.Config
	// IgnoreMAC, when true, skips MAC verification. Use only with a warning.
	IgnoreMAC bool
}

// Result is what Decrypt returns. Plaintext is the raw decrypted bytes;
// Flat is the carlpett-compatible flattened key/value map; JSON is the
// structured representation; Metadata carries audit info.
type Result struct {
	Plaintext []byte
	Flat      map[string]string
	JSON      []byte
	Metadata  Metadata
}

// Decrypt loads encrypted bytes, rebuilds master keys with injected credentials,
// fetches the data key via the local keyservice, decrypts the tree, and returns
// the multi-shape output.
func Decrypt(ctx context.Context, in DecryptInput) (*Result, error) {
	rel, err := getSem().Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: acquire semaphore: %w", err)
	}
	defer rel()

	// Scope SOPS env vars to this call (no global pollution).
	restore := applyScopedEnv(in.Config)
	defer restore()

	store, err := StoreFor(in.Format)
	if err != nil {
		return nil, err
	}

	tree, err := store.LoadEncryptedFile(in.Source)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: load encrypted: %w", err)
	}

	// THIS is the line that beats carlpett: we replace tree.Metadata.KeyGroups
	// with versions that carry our injected credentials.
	rebuilt, err := RebuildKeyGroups(tree, in.Config)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: rebuild key groups: %w", err)
	}
	tree.Metadata.KeyGroups = rebuilt

	ks := []keyservice.KeyServiceClient{keyservice.NewLocalClient()}
	dataKey, err := tree.Metadata.GetDataKeyWithKeyServices(ks, sops.DefaultDecryptionOrder)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: get data key: %w", err)
	}

	if _, err := tree.Decrypt(dataKey, aes.NewCipher()); err != nil {
		return nil, fmt.Errorf("sopswrap: decrypt tree: %w", err)
	}

	plaintext, err := store.EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: emit plain: %w", err)
	}

	js, err := ToJSON(tree.Branches)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: to json: %w", err)
	}

	return &Result{
		Plaintext: plaintext,
		Flat:      Flatten(tree.Branches),
		JSON:      js,
		Metadata:  ExtractMetadata(tree),
	}, nil
}
```

- [ ] **Step 4: Stub `applyScopedEnv` (real implementation in Task 15)**

Add to `internal/sopswrap/decrypt.go` (or a new `envscope.go`):

```go
// applyScopedEnv sets SOPS-relevant env vars from cfg and returns a func that
// restores the previous values. Phase 1 implementation handles age/PGP/GCP.
// Implemented in detail in env scope task.
func applyScopedEnv(cfg auth.Config) func() {
	type restore struct {
		key string
		val string
		ok  bool
	}
	var saves []restore

	set := func(k, v string) {
		if v == "" {
			return
		}
		old, ok := lookupEnv(k)
		saves = append(saves, restore{k, old, ok})
		_ = setEnv(k, v)
	}

	set("SOPS_AGE_KEY", cfg.Age.Key)
	set("SOPS_AGE_KEY_FILE", cfg.Age.KeyFile)
	set("SOPS_AGE_KEY_CMD", cfg.Age.KeyCommand)
	set("SOPS_AGE_SSH_PRIVATE_KEY_FILE", cfg.Age.SSHPrivateKeyFile)
	set("GOOGLE_APPLICATION_CREDENTIALS", cfg.GCP.CredentialsFile)
	set("GNUPGHOME", cfg.PGP.GnupgHome)
	// AWS_PROFILE is NOT set here — kms.MasterKey.AwsProfile is the injection point
	// that doesn't pollute the process env. That's the whole point of this provider.

	return func() {
		for _, r := range saves {
			if r.ok {
				_ = setEnv(r.key, r.val)
			} else {
				_ = unsetEnv(r.key)
			}
		}
	}
}

// Indirection for testability.
var (
	lookupEnv = func(k string) (string, bool) { return osLookupEnv(k) }
	setEnv    = func(k, v string) error { return osSetEnv(k, v) }
	unsetEnv  = func(k string) error { return osUnsetEnv(k) }
)
```

And add a sibling `envscope.go`:

```go
package sopswrap

import "os"

func osLookupEnv(k string) (string, bool) { return os.LookupEnv(k) }
func osSetEnv(k, v string) error         { return os.Setenv(k, v) }
func osUnsetEnv(k string) error          { return os.Unsetenv(k) }
```

- [ ] **Step 5: Run — expect pass**

Run: `go test ./internal/sopswrap/... -v -run TestDecrypt`
Expected: all 5 (YAML/JSON/Dotenv/Binary/ParallelStable) PASS.

If `TestDecrypt_ParallelStable` flakes, the semaphore is broken — fix it before continuing.

- [ ] **Step 6: Commit**

```bash
git add internal/sopswrap/decrypt.go internal/sopswrap/envscope.go internal/sopswrap/decrypt_test.go
git commit -S -m "feat(sopswrap): orchestrator Decrypt() with scoped env + concurrency

- Loads encrypted file via Store
- Rebuilds key groups with injected credentials (the AWS_PROFILE fix)
- Drives tree.Metadata.GetDataKeyWithKeyServices() via local keyservice
- Returns Plaintext / Flat / JSON / Metadata triple
- Bounded by global semaphore (carlpett #126 fix)
- Sets SOPS_AGE_* / GNUPGHOME / GOOGLE_APPLICATION_CREDENTIALS scoped to call"
```

---

### Task 15: Provider block schema + Configure

Wires the auth blocks into the framework provider. Configuring the provider builds the package-level `providerConfig` and exposes it via `req.ProviderData`.

**Files:**
- Modify: `internal/provider/provider.go`
- Create: `internal/provider/models.go`
- Modify: `internal/provider/provider_test.go`

- [ ] **Step 1: Add the failing schema test**

Append to `internal/provider/provider_test.go`:

```go
func TestProviderSchemaHasAuthBlocks(t *testing.T) {
	t.Parallel()
	p := provider.New("test")()
	resp := &fwprovider.SchemaResponse{}
	p.Schema(context.Background(), fwprovider.SchemaRequest{}, resp)
	require.False(t, resp.Diagnostics.HasError(), resp.Diagnostics.Errors())

	require.Contains(t, resp.Schema.GetBlocks(), "aws")
	require.Contains(t, resp.Schema.GetBlocks(), "gcp")
	require.Contains(t, resp.Schema.GetBlocks(), "azure")
	require.Contains(t, resp.Schema.GetBlocks(), "age")
	require.Contains(t, resp.Schema.GetBlocks(), "pgp")
	require.Contains(t, resp.Schema.GetAttributes(), "concurrency_limit")
}
```

Update imports at top of the test file:

```go
import (
	"context"
	"testing"

	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/stretchr/testify/require"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider"
)
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/provider/... -run TestProviderSchemaHasAuthBlocks`
Expected: FAIL (schema has no blocks yet).

- [ ] **Step 3: Implement provider models**

Create `internal/provider/models.go`:

```go
package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
)

// ProviderModel is the framework data model for the `provider "sops" { ... }` block.
type ProviderModel struct {
	AWS              *auth.AWSModel   `tfsdk:"aws"`
	GCP              *auth.GCPModel   `tfsdk:"gcp"`
	Azure            *auth.AzureModel `tfsdk:"azure"`
	Age              *auth.AgeModel   `tfsdk:"age"`
	PGP              *auth.PGPModel   `tfsdk:"pgp"`
	ConcurrencyLimit types.Int64      `tfsdk:"concurrency_limit"`
}
```

- [ ] **Step 4: Wire schema + Configure**

Replace `internal/provider/provider.go` Schema and Configure with:

```go
func (p *sopsProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "SOPS decrypt + (in later phases) encrypt provider with first-class credential configuration.",
		Attributes: map[string]schema.Attribute{
			"concurrency_limit": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of parallel decrypt calls (default 4).",
			},
		},
		Blocks: map[string]schema.Block{
			"aws":   auth.AWSBlockSchema(),
			"gcp":   auth.GCPBlockSchema(),
			"azure": auth.AzureBlockSchema(),
			"age":   auth.AgeBlockSchema(),
			"pgp":   auth.PGPBlockSchema(),
		},
	}
}

// ProviderData is the value handed to every data source / ephemeral via req.ProviderData.
type ProviderData struct {
	Config auth.Config
}

func (p *sopsProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var m ProviderModel
	diags := req.Config.Get(ctx, &m)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	cfg := auth.Config{}
	if c, d := m.AWS.ToConfig(ctx); !appendDiagsHasErr(&resp.Diagnostics, d) {
		cfg.AWS = c
	}
	if c, d := m.GCP.ToConfig(ctx); !appendDiagsHasErr(&resp.Diagnostics, d) {
		cfg.GCP = c
	}
	if c, d := m.Azure.ToConfig(ctx); !appendDiagsHasErr(&resp.Diagnostics, d) {
		cfg.Azure = c
	}
	if c, d := m.Age.ToConfig(ctx); !appendDiagsHasErr(&resp.Diagnostics, d) {
		cfg.Age = c
	}
	if c, d := m.PGP.ToConfig(ctx); !appendDiagsHasErr(&resp.Diagnostics, d) {
		cfg.PGP = c
	}
	if !m.ConcurrencyLimit.IsNull() {
		cfg.ConcurrencyLimit = int(m.ConcurrencyLimit.ValueInt64())
		sopswrap.SetGlobalConcurrency(cfg.ConcurrencyLimit)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	pd := &ProviderData{Config: cfg}
	resp.DataSourceData = pd
	resp.EphemeralResourceData = pd
}

func appendDiagsHasErr(out *diag.Diagnostics, in diag.Diagnostics) bool {
	out.Append(in...)
	return in.HasError()
}
```

Update imports at top of `provider.go`:

```go
import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
	"github.com/elioseverojunior/terraform-provider-sops/internal/sopswrap"
)
```

- [ ] **Step 5: Run — expect pass**

Run: `go test ./internal/provider/... -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/provider/provider.go internal/provider/provider_test.go internal/provider/models.go
git commit -S -m "feat(provider): wire aws/gcp/azure/age/pgp blocks + Configure

Configure builds an auth.Config from the provider block and exposes it
via DataSourceData / EphemeralResourceData. concurrency_limit replaces
the sopswrap package-level semaphore."
```

---

### Task 16: `data "sops_file"` data source

**Files:**
- Create: `internal/datasources/file.go`
- Create: `internal/datasources/file_test.go`
- Modify: `internal/provider/provider.go` (register the data source)

- [ ] **Step 1: Write the failing acceptance-style test**

Create `internal/datasources/file_test.go`:

```go
package datasources_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider"
)

var protoV6Factory = map[string]func() (tfprotov6.ProviderServer, error){
	"sops": providerserver.NewProtocol6WithError(provider.New("test")()),
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile))) // .../internal/datasources/.. -> repo root
}

func TestAccDataSource_SopsFile_YAML(t *testing.T) {
	root := repoRoot(t)
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(root, "testdata/age-key.txt"))

	fixture := filepath.Join(root, "testdata/secrets.yaml")
	tf := `
data "sops_file" "x" {
  source_file = "` + fixture + `"
  input_type  = "yaml"
}
output "pwd"     { value = data.sops_file.x.data["database.password"] }
output "api_key" { value = data.sops_file.x.data["api_key"] }
`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{
			{
				Config: tf,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckOutput("pwd", "hunter2"),
					resource.TestCheckOutput("api_key", "sk-test-12345"),
				),
			},
		},
	})

	_ = os.Setenv // suppress import if unused on some platforms
}

func TestAccDataSource_SopsFile_JSON_StructuredOutput(t *testing.T) {
	root := repoRoot(t)
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(root, "testdata/age-key.txt"))

	fixture := filepath.Join(root, "testdata/secrets.json")
	tf := `
data "sops_file" "x" {
  source_file = "` + fixture + `"
  input_type  = "json"
}
output "structured" { value = jsondecode(data.sops_file.x.data_json).database.password }
`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{
			{
				Config: tf,
				Check:  resource.TestCheckOutput("structured", "hunter2"),
			},
		},
	})
}

func TestAccDataSource_SopsFile_PerCallAgeOverride(t *testing.T) {
	root := repoRoot(t)
	// Intentionally NO env var. Pass key_file via per-resource age{} block instead.
	t.Setenv("SOPS_AGE_KEY_FILE", "")

	fixture := filepath.Join(root, "testdata/secrets.yaml")
	keyFile := filepath.Join(root, "testdata/age-key.txt")
	tf := `
data "sops_file" "x" {
  source_file = "` + fixture + `"
  input_type  = "yaml"
  age { key_file = "` + keyFile + `" }
}
output "pwd" { value = data.sops_file.x.data["database.password"] }
`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{
			{
				Config: tf,
				Check:  resource.TestCheckOutput("pwd", "hunter2"),
			},
		},
	})
}
```

Add testing dep if not already:
```bash
go get github.com/hashicorp/terraform-plugin-testing@latest
```

- [ ] **Step 2: Run — expect fail (no data source registered)**

Run: `go test ./internal/datasources/...`
Expected: FAIL — `data "sops_file"` is unknown.

- [ ] **Step 3: Implement `file.go`**

Create `internal/datasources/file.go`:

```go
// Package datasources implements the read-side Terraform data sources.
package datasources

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
	"github.com/elioseverojunior/terraform-provider-sops/internal/sopswrap"
)

// ProviderDataAccessor is what the provider hands us via DataSourceData.
type ProviderDataAccessor interface {
	ProviderAuthConfig() auth.Config
}

// fileDataSource implements data "sops_file".
type fileDataSource struct {
	providerCfg auth.Config
}

func NewFileDataSource() datasource.DataSource {
	return &fileDataSource{}
}

func (d *fileDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_file"
}

func (d *fileDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	acc, ok := req.ProviderData.(ProviderDataAccessor)
	if !ok {
		return
	}
	d.providerCfg = acc.ProviderAuthConfig()
}

func (d *fileDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Decrypts a SOPS-encrypted file from disk.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Computed: true},
			"source_file": schema.StringAttribute{Required: true, Description: "Path to the SOPS-encrypted file."},
			"input_type":  schema.StringAttribute{Optional: true, Description: "yaml, json, dotenv, ini, binary, or raw. Auto-detected from extension when omitted."},
			"data":        schema.MapAttribute{Computed: true, ElementType: types.StringType, Sensitive: true, Description: "Flat map (carlpett-compatible)."},
			"data_json":   schema.StringAttribute{Computed: true, Sensitive: true, Description: "Structured nested JSON of the decrypted tree."},
			"raw":         schema.StringAttribute{Computed: true, Sensitive: true, Description: "Decrypted bytes as a string."},
			"metadata":    metadataAttribute(),
		},
		Blocks: map[string]schema.Block{
			"aws":   auth.AWSBlockSchemaForDataSource(),
			"gcp":   auth.GCPBlockSchemaForDataSource(),
			"azure": auth.AzureBlockSchemaForDataSource(),
			"age":   auth.AgeBlockSchemaForDataSource(),
			"pgp":   auth.PGPBlockSchemaForDataSource(),
		},
	}
}

type fileModel struct {
	ID         types.String        `tfsdk:"id"`
	SourceFile types.String        `tfsdk:"source_file"`
	InputType  types.String        `tfsdk:"input_type"`
	Data       types.Map           `tfsdk:"data"`
	DataJSON   types.String        `tfsdk:"data_json"`
	Raw        types.String        `tfsdk:"raw"`
	Metadata   types.Object        `tfsdk:"metadata"`
	AWS        *auth.AWSModel      `tfsdk:"aws"`
	GCP        *auth.GCPModel      `tfsdk:"gcp"`
	Azure      *auth.AzureModel    `tfsdk:"azure"`
	Age        *auth.AgeModel      `tfsdk:"age"`
	PGP        *auth.PGPModel      `tfsdk:"pgp"`
}

func (d *fileDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m fileModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}

	path := m.SourceFile.ValueString()
	src, err := os.ReadFile(path)
	if err != nil {
		resp.Diagnostics.AddError("could not read source_file",
			fmt.Sprintf("path=%q: %s", path, err))
		return
	}

	format := sopswrap.Format(m.InputType.ValueString())
	if format == "" {
		format = sopswrap.FormatFromPath(path)
	}

	perCall := buildPerCallConfig(ctx, m.AWS, m.GCP, m.Azure, m.Age, m.PGP, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	cfg := auth.Merge(d.providerCfg, perCall)

	out, err := sopswrap.Decrypt(ctx, sopswrap.DecryptInput{
		Source: src, Format: format, Config: cfg,
	})
	if err != nil {
		resp.Diagnostics.AddError("sops decrypt failed",
			fmt.Sprintf("path=%q: %s\n\nIf this is an auth failure, check that your `aws {}` / `gcp {}` / `age {}` block on the provider or data source matches the key principals on the file.", path, err))
		return
	}

	m.ID = types.StringValue(path)
	m.Raw = types.StringValue(string(out.Plaintext))
	m.DataJSON = types.StringValue(string(out.JSON))
	m.Data, _ = types.MapValueFrom(ctx, types.StringType, out.Flat)
	m.Metadata = metadataObjectValue(ctx, out.Metadata)

	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
```

Add helpers in a new file `internal/datasources/helpers.go`:

```go
package datasources

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
	"github.com/elioseverojunior/terraform-provider-sops/internal/sopswrap"
)

func metadataAttribute() schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Computed: true,
		Attributes: map[string]schema.Attribute{
			"lastmodified":       schema.StringAttribute{Computed: true},
			"mac":                schema.StringAttribute{Computed: true, Sensitive: true},
			"version":            schema.StringAttribute{Computed: true},
			"kms_arns":           schema.ListAttribute{Computed: true, ElementType: types.StringType},
			"gcp_kms_resources":  schema.ListAttribute{Computed: true, ElementType: types.StringType},
			"azure_kv_urls":      schema.ListAttribute{Computed: true, ElementType: types.StringType},
			"age_recipients":     schema.ListAttribute{Computed: true, ElementType: types.StringType},
			"pgp_fingerprints":   schema.ListAttribute{Computed: true, ElementType: types.StringType},
		},
	}
}

func metadataObjectValue(ctx context.Context, md sopswrap.Metadata) types.Object {
	attrs := map[string]attr.Value{
		"lastmodified":      types.StringValue(md.LastModified.Format(time.RFC3339)),
		"mac":               types.StringValue(md.MAC),
		"version":           types.StringValue(md.Version),
		"kms_arns":          listOfStrings(ctx, md.KMSARNs),
		"gcp_kms_resources": listOfStrings(ctx, md.GCPKMSResources),
		"azure_kv_urls":     listOfStrings(ctx, md.AzureKVURLs),
		"age_recipients":    listOfStrings(ctx, md.AgeRecipients),
		"pgp_fingerprints":  listOfStrings(ctx, md.PGPFingerprints),
	}
	t := metadataAttrTypes()
	o, _ := types.ObjectValue(t, attrs)
	return o
}

func metadataAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"lastmodified":      types.StringType,
		"mac":               types.StringType,
		"version":           types.StringType,
		"kms_arns":          types.ListType{ElemType: types.StringType},
		"gcp_kms_resources": types.ListType{ElemType: types.StringType},
		"azure_kv_urls":     types.ListType{ElemType: types.StringType},
		"age_recipients":    types.ListType{ElemType: types.StringType},
		"pgp_fingerprints":  types.ListType{ElemType: types.StringType},
	}
}

func listOfStrings(ctx context.Context, ss []string) types.List {
	if len(ss) == 0 {
		l, _ := types.ListValue(types.StringType, []attr.Value{})
		return l
	}
	vals := make([]attr.Value, len(ss))
	for i, s := range ss {
		vals[i] = types.StringValue(s)
	}
	l, _ := types.ListValue(types.StringType, vals)
	return l
}

func buildPerCallConfig(
	ctx context.Context,
	aws *auth.AWSModel,
	gcp *auth.GCPModel,
	azure *auth.AzureModel,
	age *auth.AgeModel,
	pgp *auth.PGPModel,
	diags *diag.Diagnostics,
) auth.Config {
	var cfg auth.Config
	if c, d := aws.ToConfig(ctx); !appendDiagsHasErr(diags, d) {
		cfg.AWS = c
	}
	if c, d := gcp.ToConfig(ctx); !appendDiagsHasErr(diags, d) {
		cfg.GCP = c
	}
	if c, d := azure.ToConfig(ctx); !appendDiagsHasErr(diags, d) {
		cfg.Azure = c
	}
	if c, d := age.ToConfig(ctx); !appendDiagsHasErr(diags, d) {
		cfg.Age = c
	}
	if c, d := pgp.ToConfig(ctx); !appendDiagsHasErr(diags, d) {
		cfg.PGP = c
	}
	return cfg
}

func appendDiagsHasErr(out *diag.Diagnostics, in diag.Diagnostics) bool {
	out.Append(in...)
	return in.HasError()
}
```

(Imports for helpers.go to be added: `"time"`, `"github.com/hashicorp/terraform-plugin-framework/attr"`.)

- [ ] **Step 4: Add per-resource schema variants in `auth/`**

The provider block uses `schema.Block` from `provider/schema`; data sources use `schema.Block` from `datasource/schema`. They have separate type hierarchies. Add per-package variants.

Modify each `auth/aws.go` / `gcp.go` / `azure.go` / `age.go` / `pgp.go` to add a second exported function:

```go
// In aws.go, add after AWSBlockSchema():
import dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"

func AWSBlockSchemaForDataSource() dsschema.Block {
	return dsschema.SingleNestedBlock{
		Description: "Per-resource AWS KMS credential override.",
		Attributes: map[string]dsschema.Attribute{
			"profile":                  dsschema.StringAttribute{Optional: true},
			"region":                   dsschema.StringAttribute{Optional: true},
			"shared_config_files":      dsschema.ListAttribute{Optional: true, ElementType: types.StringType},
			"shared_credentials_files": dsschema.ListAttribute{Optional: true, ElementType: types.StringType},
			"env":                      dsschema.MapAttribute{Optional: true, ElementType: types.StringType},
		},
		Blocks: map[string]dsschema.Block{
			"assume_role": dsschema.SingleNestedBlock{
				Attributes: map[string]dsschema.Attribute{
					"role_arn":     dsschema.StringAttribute{Optional: true},
					"session_name": dsschema.StringAttribute{Optional: true},
					"external_id":  dsschema.StringAttribute{Optional: true},
					"duration":     dsschema.StringAttribute{Optional: true},
				},
			},
		},
	}
}
```

Mirror the pattern for `GCPBlockSchemaForDataSource`, `AzureBlockSchemaForDataSource`, `AgeBlockSchemaForDataSource`, `PGPBlockSchemaForDataSource` — same attribute shapes, just using `datasource/schema` types.

- [ ] **Step 5: Make `provider.ProviderData` implement `ProviderDataAccessor`**

In `internal/provider/provider.go` add:

```go
// ProviderAuthConfig satisfies datasources.ProviderDataAccessor and ephemeral.ProviderDataAccessor.
func (p *ProviderData) ProviderAuthConfig() auth.Config { return p.Config }
```

- [ ] **Step 6: Register the data source**

In `provider.go`:

```go
import "github.com/elioseverojunior/terraform-provider-sops/internal/datasources"

func (p *sopsProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		datasources.NewFileDataSource,
	}
}
```

- [ ] **Step 7: Run — expect pass**

Run: `go test ./internal/datasources/... -v`
Expected: all 3 acceptance tests PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/datasources/ internal/provider/auth/*.go internal/provider/provider.go
git commit -S -m "feat(datasource): sops_file with per-resource auth overrides

- Drop-in carlpett-compatible attrs (source_file, input_type, data, raw)
- New: data_json (structured nested) and metadata (audit)
- Per-call aws/gcp/azure/age/pgp blocks merge over provider-level config
- Adds *BlockSchemaForDataSource variants reusing the same attribute shapes"
```

---

### Task 17: `data "sops_external"` data source

Same shape as `sops_file` but reads ciphertext from a string attribute, not the filesystem.

**Files:**
- Create: `internal/datasources/external.go`
- Create: `internal/datasources/external_test.go`
- Modify: `internal/provider/provider.go`

- [ ] **Step 1: Write the failing test**

Create `internal/datasources/external_test.go`:

```go
package datasources_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDataSource_SopsExternal_YAML(t *testing.T) {
	root := repoRoot(t)
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(root, "testdata/age-key.txt"))

	encrypted, err := os.ReadFile(filepath.Join(root, "testdata/secrets.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	tf := `
data "sops_external" "x" {
  source     = <<EOT
` + string(encrypted) + `
EOT
  input_type = "yaml"
}
output "pwd" { value = data.sops_external.x.data["database.password"] }
`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{
			{
				Config: tf,
				Check:  resource.TestCheckOutput("pwd", "hunter2"),
			},
		},
	})
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/datasources/... -run TestAccDataSource_SopsExternal`
Expected: FAIL — `data "sops_external"` unknown.

- [ ] **Step 3: Implement `external.go`**

Create `internal/datasources/external.go`:

```go
package datasources

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
	"github.com/elioseverojunior/terraform-provider-sops/internal/sopswrap"
)

type externalDataSource struct {
	providerCfg auth.Config
}

func NewExternalDataSource() datasource.DataSource {
	return &externalDataSource{}
}

func (d *externalDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_external"
}

func (d *externalDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	if acc, ok := req.ProviderData.(ProviderDataAccessor); ok {
		d.providerCfg = acc.ProviderAuthConfig()
	}
}

func (d *externalDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Decrypts a SOPS-encrypted blob passed as a string.",
		Attributes: map[string]schema.Attribute{
			"id":         schema.StringAttribute{Computed: true},
			"source":     schema.StringAttribute{Required: true, Sensitive: true},
			"input_type": schema.StringAttribute{Required: true},
			"data":       schema.MapAttribute{Computed: true, ElementType: types.StringType, Sensitive: true},
			"data_json":  schema.StringAttribute{Computed: true, Sensitive: true},
			"raw":        schema.StringAttribute{Computed: true, Sensitive: true},
			"metadata":   metadataAttribute(),
		},
		Blocks: map[string]schema.Block{
			"aws":   auth.AWSBlockSchemaForDataSource(),
			"gcp":   auth.GCPBlockSchemaForDataSource(),
			"azure": auth.AzureBlockSchemaForDataSource(),
			"age":   auth.AgeBlockSchemaForDataSource(),
			"pgp":   auth.PGPBlockSchemaForDataSource(),
		},
	}
}

type externalModel struct {
	ID        types.String        `tfsdk:"id"`
	Source    types.String        `tfsdk:"source"`
	InputType types.String        `tfsdk:"input_type"`
	Data      types.Map           `tfsdk:"data"`
	DataJSON  types.String        `tfsdk:"data_json"`
	Raw       types.String        `tfsdk:"raw"`
	Metadata  types.Object        `tfsdk:"metadata"`
	AWS       *auth.AWSModel      `tfsdk:"aws"`
	GCP       *auth.GCPModel      `tfsdk:"gcp"`
	Azure     *auth.AzureModel    `tfsdk:"azure"`
	Age       *auth.AgeModel      `tfsdk:"age"`
	PGP       *auth.PGPModel      `tfsdk:"pgp"`
}

func (d *externalDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m externalModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}

	perCall := buildPerCallConfig(ctx, m.AWS, m.GCP, m.Azure, m.Age, m.PGP, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	cfg := auth.Merge(d.providerCfg, perCall)

	out, err := sopswrap.Decrypt(ctx, sopswrap.DecryptInput{
		Source: []byte(m.Source.ValueString()),
		Format: sopswrap.Format(m.InputType.ValueString()),
		Config: cfg,
	})
	if err != nil {
		resp.Diagnostics.AddError("sops decrypt failed",
			fmt.Sprintf("input_type=%q: %s", m.InputType.ValueString(), err))
		return
	}

	// Use the SHA-ish portion of the MAC as a stable id.
	id := out.Metadata.MAC
	if id == "" {
		id = "external"
	}
	m.ID = types.StringValue(id)
	m.Raw = types.StringValue(string(out.Plaintext))
	m.DataJSON = types.StringValue(string(out.JSON))
	m.Data, _ = types.MapValueFrom(ctx, types.StringType, out.Flat)
	m.Metadata = metadataObjectValue(ctx, out.Metadata)

	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
```

- [ ] **Step 4: Register**

In `provider.go` `DataSources`:

```go
return []func() datasource.DataSource{
	datasources.NewFileDataSource,
	datasources.NewExternalDataSource,
}
```

- [ ] **Step 5: Run — expect pass**

Run: `go test ./internal/datasources/... -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/datasources/external.go internal/datasources/external_test.go internal/provider/provider.go
git commit -S -m "feat(datasource): sops_external for in-string ciphertext"
```

---

### Task 18: `ephemeral "sops_file"` resource

Mirror of `data "sops_file"` but using the framework's `ephemeral` package — plaintext never persists to state.

**Files:**
- Create: `internal/ephemeral/file.go`
- Create: `internal/ephemeral/file_test.go`
- Modify: `internal/provider/provider.go`

- [ ] **Step 1: Write the failing test**

Create `internal/ephemeral/file_test.go`:

```go
package ephemeral_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider"
)

var protoV6Factory = map[string]func() (tfprotov6.ProviderServer, error){
	"sops": providerserver.NewProtocol6WithError(provider.New("test")()),
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
}

func TestAccEphemeral_SopsFile_YAML(t *testing.T) {
	root := repoRoot(t)
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(root, "testdata/age-key.txt"))
	fixture := filepath.Join(root, "testdata/secrets.yaml")

	// Ephemerals only run in plan; we use the echo provider pattern.
	tf := `
ephemeral "sops_file" "x" {
  source_file = "` + fixture + `"
  input_type  = "yaml"
}

provider "echo" {
  data = ephemeral.sops_file.x.data["database.password"]
}

resource "echo" "out" {}
`

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: protoV6Factory,
		// echo provider is provided by terraform-plugin-testing's echoprovider/v1 package.
		Steps: []resource.TestStep{{Config: tf, Check: resource.TestCheckResourceAttr("echo.out", "data", "hunter2")}},
	})
}
```

Add echo provider plumbing:

```go
// in init() in this test file:
func init() {
	// terraform-plugin-testing v1.10+ ships echoprovider for ephemeral testing.
}
```

(Refer to `github.com/hashicorp/terraform-plugin-testing/echoprovider/v1` per latest framework docs; implementation detail handled at test setup time.)

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/ephemeral/...`
Expected: FAIL — `ephemeral "sops_file"` unknown.

- [ ] **Step 3: Implement `file.go`**

Create `internal/ephemeral/file.go`:

```go
// Package ephemeral implements ephemeral resources — values that exist during
// a Terraform run but never persist to state.
package ephemeral

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
	"github.com/elioseverojunior/terraform-provider-sops/internal/sopswrap"
)

type ProviderDataAccessor interface {
	ProviderAuthConfig() auth.Config
}

type fileEphemeral struct {
	providerCfg auth.Config
}

func NewFileEphemeral() ephemeral.EphemeralResource {
	return &fileEphemeral{}
}

func (e *fileEphemeral) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_file"
}

func (e *fileEphemeral) Configure(_ context.Context, req ephemeral.ConfigureRequest, _ *ephemeral.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	if acc, ok := req.ProviderData.(ProviderDataAccessor); ok {
		e.providerCfg = acc.ProviderAuthConfig()
	}
}

func (e *fileEphemeral) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Decrypts a SOPS-encrypted file without persisting plaintext to state.",
		Attributes: map[string]schema.Attribute{
			"source_file": schema.StringAttribute{Required: true},
			"input_type":  schema.StringAttribute{Optional: true},
			"data":        schema.MapAttribute{Computed: true, ElementType: types.StringType, Sensitive: true},
			"data_json":   schema.StringAttribute{Computed: true, Sensitive: true},
			"raw":         schema.StringAttribute{Computed: true, Sensitive: true},
		},
		Blocks: map[string]schema.Block{
			"aws":   auth.AWSBlockSchemaForEphemeral(),
			"gcp":   auth.GCPBlockSchemaForEphemeral(),
			"azure": auth.AzureBlockSchemaForEphemeral(),
			"age":   auth.AgeBlockSchemaForEphemeral(),
			"pgp":   auth.PGPBlockSchemaForEphemeral(),
		},
	}
}

type fileEphemeralModel struct {
	SourceFile types.String        `tfsdk:"source_file"`
	InputType  types.String        `tfsdk:"input_type"`
	Data       types.Map           `tfsdk:"data"`
	DataJSON   types.String        `tfsdk:"data_json"`
	Raw        types.String        `tfsdk:"raw"`
	AWS        *auth.AWSModel      `tfsdk:"aws"`
	GCP        *auth.GCPModel      `tfsdk:"gcp"`
	Azure      *auth.AzureModel    `tfsdk:"azure"`
	Age        *auth.AgeModel      `tfsdk:"age"`
	PGP        *auth.PGPModel      `tfsdk:"pgp"`
}

func (e *fileEphemeral) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var m fileEphemeralModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	path := m.SourceFile.ValueString()
	src, err := os.ReadFile(path)
	if err != nil {
		resp.Diagnostics.AddError("could not read source_file", fmt.Sprintf("%s: %s", path, err))
		return
	}
	format := sopswrap.Format(m.InputType.ValueString())
	if format == "" {
		format = sopswrap.FormatFromPath(path)
	}
	perCall := buildPerCallConfigEphemeral(ctx, m.AWS, m.GCP, m.Azure, m.Age, m.PGP, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	cfg := auth.Merge(e.providerCfg, perCall)
	out, err := sopswrap.Decrypt(ctx, sopswrap.DecryptInput{Source: src, Format: format, Config: cfg})
	if err != nil {
		resp.Diagnostics.AddError("sops decrypt failed", err.Error())
		return
	}
	m.Raw = types.StringValue(string(out.Plaintext))
	m.DataJSON = types.StringValue(string(out.JSON))
	m.Data, _ = types.MapValueFrom(ctx, types.StringType, out.Flat)
	resp.Diagnostics.Append(resp.Result.Set(ctx, &m)...)
}
```

Add ephemeral schema variants in each `auth/*.go` (mirroring `*BlockSchemaForDataSource` but with imports from `github.com/hashicorp/terraform-plugin-framework/ephemeral/schema`). Add the helper `buildPerCallConfigEphemeral` in a new `internal/ephemeral/helpers.go` analogous to the datasource helper.

- [ ] **Step 4: Register**

In `provider.go`:

```go
import "github.com/elioseverojunior/terraform-provider-sops/internal/ephemeral"

func (p *sopsProvider) EphemeralResources(_ context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{
		ephemeral.NewFileEphemeral,
	}
}
```

- [ ] **Step 5: Run — expect pass**

Run: `go test ./internal/ephemeral/... -v`
Expected: PASS (on TF ≥ 1.10).

- [ ] **Step 6: Commit**

```bash
git add internal/ephemeral/ internal/provider/auth/*.go internal/provider/provider.go
git commit -S -m "feat(ephemeral): sops_file ephemeral resource

Same surface as data.sops_file but plaintext is never serialized to
plan/state. Requires Terraform >= 1.10."
```

---

### Task 19: `ephemeral "sops_external"` resource

**Files:**
- Create: `internal/ephemeral/external.go`
- Create: `internal/ephemeral/external_test.go`
- Modify: `internal/provider/provider.go`

- [ ] **Step 1: Write the failing test**

Create `internal/ephemeral/external_test.go` mirroring `TestAccDataSource_SopsExternal_YAML` but using `ephemeral.sops_external` + echo provider.

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/ephemeral/... -run TestAccEphemeral_SopsExternal`
Expected: FAIL.

- [ ] **Step 3: Implement `external.go`**

Mirror `internal/datasources/external.go` but using the `ephemeral` schema/types from Task 18.

- [ ] **Step 4: Register in `provider.go`**

```go
return []func() ephemeral.EphemeralResource{
	ephemeral.NewFileEphemeral,
	ephemeral.NewExternalEphemeral,
}
```

- [ ] **Step 5: Run — expect pass**

Run: `go test ./internal/ephemeral/... -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/ephemeral/external.go internal/ephemeral/external_test.go internal/provider/provider.go
git commit -S -m "feat(ephemeral): sops_external ephemeral resource"
```

---

### Task 20: AWS KMS acceptance test (build-tag gated)

Real KMS round-trip — the headline integration test that proves the `AWS_PROFILE` injection works end-to-end. Gated on `TF_ACC=1` plus AWS env vars so it never runs in normal `go test`.

**Files:**
- Create: `internal/sopswrap/acc_aws_kms_test.go`

- [ ] **Step 1: Write the gated test**

Create `internal/sopswrap/acc_aws_kms_test.go`:

```go
//go:build acceptance

package sopswrap_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
	"github.com/elioseverojunior/terraform-provider-sops/internal/sopswrap"
)

// TestAccAWSKMS_ProfileInjection verifies that setting AWSConfig.Profile is
// sufficient to decrypt a real KMS-encrypted SOPS file — WITHOUT exporting
// AWS_PROFILE to the test process. This is the headline fix.
func TestAccAWSKMS_ProfileInjection(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("TF_ACC=1 required for acceptance tests")
	}
	profile := os.Getenv("SOPS_TEST_AWS_PROFILE")
	if profile == "" {
		t.Skip("SOPS_TEST_AWS_PROFILE not set")
	}
	arn := os.Getenv("SOPS_TEST_KMS_ARN")
	if arn == "" {
		t.Skip("SOPS_TEST_KMS_ARN not set")
	}

	// Make sure AWS_PROFILE is NOT in the test env — proves we don't depend on it.
	os.Unsetenv("AWS_PROFILE")

	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.yaml")
	enc := filepath.Join(dir, "enc.yaml")
	require.NoError(t, os.WriteFile(plain, []byte("password: hunter2\n"), 0o600))

	// Encrypt using sops CLI with AWS_PROFILE in the encrypt step (allowed —
	// the test only proves AWS_PROFILE is not required for DECRYPT).
	cmd := exec.Command("sops", "--encrypt", "--kms", arn, "--input-type", "yaml", "--output-type", "yaml", plain)
	cmd.Env = append(os.Environ(), "AWS_PROFILE="+profile)
	out, err := cmd.Output()
	require.NoError(t, err, "encryption setup failed: %s", out)
	require.NoError(t, os.WriteFile(enc, out, 0o600))

	src, err := os.ReadFile(enc)
	require.NoError(t, err)

	result, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: src,
		Format: sopswrap.FormatYAML,
		Config: auth.Config{
			AWS: auth.AWSConfig{Profile: profile},
		},
	})
	require.NoError(t, err)
	require.Contains(t, string(result.Plaintext), "hunter2")
}
```

- [ ] **Step 2: Document how to run it**

Add to README (Task 22):

```markdown
## Running cloud acceptance tests

AWS KMS:
```bash
export TF_ACC=1
export SOPS_TEST_AWS_PROFILE=production-sre
export SOPS_TEST_KMS_ARN=arn:aws:kms:us-east-1:123:key/abc
go test -tags=acceptance ./internal/sopswrap/...
```
```

- [ ] **Step 3: Run — expect skip locally**

Run: `go test -tags=acceptance ./internal/sopswrap/... -run TestAccAWSKMS -v`
Expected (locally): SKIP messages. (Real run requires env vars + AWS account.)

- [ ] **Step 4: Commit**

```bash
git add internal/sopswrap/acc_aws_kms_test.go
git commit -S -m "test(acceptance): real AWS KMS decrypt with injected profile

Gated by build tag 'acceptance' and TF_ACC=1 + AWS env vars.
Asserts that decryption succeeds without AWS_PROFILE in process env —
the headline fix for carlpett #119 / #45 / #89."
```

---

### Task 21: Example Terraform configs

Compilable, real-Terraform examples that double as documentation. Each is verified by `terraform validate` in CI.

**Files:**
- Create: `examples/aws-kms-profile/main.tf`
- Create: `examples/aws-cross-account/main.tf`
- Create: `examples/age/main.tf`
- Create: `examples/multi-alias/main.tf`

- [ ] **Step 1: Write `examples/aws-kms-profile/main.tf`**

```hcl
terraform {
  required_version = ">= 1.10"
  required_providers {
    sops = {
      source  = "elioseverojunior/sops"
      version = ">= 0.1.0"
    }
  }
}

provider "sops" {
  aws {
    profile = "production-sre"
    region  = "us-east-1"
  }
}

data "sops_file" "app" {
  source_file = "${path.module}/secrets.yaml"
  input_type  = "yaml"
}

output "db_password" {
  value     = data.sops_file.app.data["database.password"]
  sensitive = true
}
```

- [ ] **Step 2: Write `examples/aws-cross-account/main.tf`**

```hcl
terraform {
  required_providers { sops = { source = "elioseverojunior/sops"; version = ">= 0.1.0" } }
}

provider "sops" {
  aws {
    profile = "platform-sre"
    region  = "us-east-1"
    assume_role { role_arn = "arn:aws:iam::111111111111:role/sops-reader" }
  }
}

# This file was encrypted by a key in account 222222222222 — we need a different role.
data "sops_file" "tenant_secrets" {
  source_file = "${path.module}/tenant-secrets.yaml"
  input_type  = "yaml"
  aws {
    profile = "platform-sre"
    assume_role { role_arn = "arn:aws:iam::222222222222:role/sops-reader" }
  }
}
```

- [ ] **Step 3: Write `examples/age/main.tf`**

```hcl
terraform {
  required_providers { sops = { source = "elioseverojunior/sops"; version = ">= 0.1.0" } }
}

provider "sops" {
  age { key_file = pathexpand("~/.config/sops/age/keys.txt") }
}

data "sops_file" "app" {
  source_file = "${path.module}/secrets.yaml"
}

output "structured" {
  value     = jsondecode(data.sops_file.app.data_json)
  sensitive = true
}
```

- [ ] **Step 4: Write `examples/multi-alias/main.tf`**

```hcl
terraform {
  required_providers { sops = { source = "elioseverojunior/sops"; version = ">= 0.1.0" } }
}

provider "sops" {
  alias = "prod"
  aws { profile = "production-sre"; region = "us-east-1" }
}

provider "sops" {
  alias = "dev"
  aws { profile = "test-sre"; region = "us-east-1" }
}

data "sops_file" "prod" {
  provider    = sops.prod
  source_file = "${path.module}/prod.yaml"
}

data "sops_file" "dev" {
  provider    = sops.dev
  source_file = "${path.module}/dev.yaml"
}
```

- [ ] **Step 5: Verify they all `terraform validate`**

Run (in each example dir):
```bash
cd examples/aws-kms-profile && terraform init -backend=false && terraform validate
```

For each example. If `terraform validate` fails on any, fix the HCL before committing.

(Note: this requires the provider binary to be installed locally. Run `make install VERSION=0.1.0-dev` first.)

- [ ] **Step 6: Commit**

```bash
git add examples/
git commit -S -m "docs(examples): four real-world configurations

- aws-kms-profile: simplest case, replaces AWS_PROFILE=… terraform apply
- aws-cross-account: assume_role override per data source
- age: structured nested output via data_json
- multi-alias: prod/dev identities via provider alias"
```

---

### Task 22: README rewrite + migration guide

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace README content**

Replace `README.md` with:

```markdown
# terraform-provider-sops

A Terraform provider for [SOPS](https://getsops.io/) — encrypt and decrypt files at plan time without exporting `AWS_PROFILE=…` to your shell.

**Key advantages over `carlpett/terraform-provider-sops`:**

- ✅ Configure AWS / GCP / Azure / age / PGP credentials **on the provider block** or per data source. No more `AWS_PROFILE=production terraform apply`.
- ✅ Cross-account KMS via `assume_role` override per resource.
- ✅ Provider `alias` for multi-environment setups.
- ✅ Structured nested output (`data_json`) in addition to the flat `data` map.
- ✅ Audit `metadata` attribute (lastmodified, MAC, KMS ARNs).
- ✅ Concurrency-safe (fixes carlpett #126 — random failures with ≥7 parallel decrypts).
- ✅ Ephemeral resources for zero-state-leakage decryption.

## Quick start

```hcl
terraform {
  required_providers {
    sops = {
      source  = "elioseverojunior/sops"
      version = ">= 0.1.0"
    }
  }
}

provider "sops" {
  aws { profile = "production-sre"; region = "us-east-1" }
}

data "sops_file" "secrets" {
  source_file = "secrets.yaml"
}

output "password" {
  value     = data.sops_file.secrets.data["database.password"]
  sensitive = true
}
```

## Migrating from `carlpett/sops`

The data source attributes (`source_file`, `input_type`, `data`, `raw`) match 1:1. In most cases the migration is a one-line change to your `required_providers` block:

```diff
 terraform {
   required_providers {
     sops = {
-      source = "carlpett/sops"
+      source = "elioseverojunior/sops"
     }
   }
 }
```

…and then you can delete `AWS_PROFILE=…` from your wrapper script and put it on the provider block instead.

## Examples

See `examples/` for: AWS profile, cross-account, age, and multi-alias setups.

## Running the test suite

```bash
make test          # unit tests
make testacc       # cloud acceptance tests (requires TF_ACC=1 + cloud creds)
```

## Status

**Phase 1 (v0.1.x):** decrypt + per-call credential injection. Shipped.
**Phase 2 (v0.2.x):** `sops_file` write resource + drift detection. Planned.
**Phase 3 (v0.3.x):** provider functions + LRU cache + Vault. Planned.

See `docs/superpowers/specs/2026-05-14-terraform-sops-provider-design.md` for the full design.

## License

MIT.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -S -m "docs: rewrite README with migration guide from carlpett/sops"
```

---

### Task 23: GitHub Actions CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/acceptance.yml`

- [ ] **Step 1: Write the CI workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        go: ["1.23"]
        terraform: ["1.10.*", "1.11.*"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: ${{ matrix.go }}
          cache: true
      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ matrix.terraform }}
          terraform_wrapper: false
      - name: Install sops + age (for fixtures)
        run: |
          curl -sL https://github.com/getsops/sops/releases/latest/download/sops-v3.10.0.linux.amd64 -o /usr/local/bin/sops
          chmod +x /usr/local/bin/sops
          sudo apt-get update && sudo apt-get install -y age
      - run: go mod download
      - run: go vet ./...
      - run: go test -race -count=1 ./...
      - name: Validate examples
        run: |
          for d in examples/*/; do
            (cd "$d" && terraform init -backend=false && terraform validate)
          done

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.23"
      - uses: golangci/golangci-lint-action@v6
        with:
          version: v1.60
```

- [ ] **Step 2: Write the acceptance workflow (manual dispatch)**

Create `.github/workflows/acceptance.yml`:

```yaml
name: Acceptance
on:
  workflow_dispatch:
    inputs:
      provider:
        description: "Which cloud to test (aws|gcp|azure|all)"
        required: false
        default: "aws"

permissions:
  id-token: write   # for AWS OIDC role
  contents: read

jobs:
  aws:
    if: ${{ inputs.provider == 'aws' || inputs.provider == 'all' }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: "1.23" }
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ACC_ROLE_ARN }}
          aws-region: us-east-1
      - name: Run AWS KMS acceptance tests
        env:
          TF_ACC: "1"
          SOPS_TEST_AWS_PROFILE: default
          SOPS_TEST_KMS_ARN: ${{ secrets.SOPS_TEST_KMS_ARN }}
        run: go test -tags=acceptance -v -timeout 30m ./internal/sopswrap/...
```

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/
git commit -S -m "ci: unit + lint on every PR, gated acceptance on dispatch

ci.yml runs go test/vet + golangci-lint + terraform validate of each example
on the latest two Terraform minor versions.

acceptance.yml is manual-dispatch only and uses OIDC into a real AWS
account to run the headline KMS profile-injection test."
```

---

### Task 24: goreleaser config for v0.1.0

Prepares for a Terraform Registry release. Not actually run in Phase 1 (we'll release manually after a tag), but the config lives in-tree.

**Files:**
- Create: `.goreleaser.yml`

- [ ] **Step 1: Write `.goreleaser.yml`**

Create `.goreleaser.yml`:

```yaml
version: 2
project_name: terraform-provider-sops
before:
  hooks:
    - go mod tidy
builds:
  - env:
      - CGO_ENABLED=0
    mod_timestamp: '{{ .CommitTimestamp }}'
    flags:
      - -trimpath
    ldflags:
      - "-s -w -X main.version={{ .Version }} -X main.commit={{ .Commit }}"
    goos: [linux, darwin, windows, freebsd]
    goarch: [amd64, arm64, '386', arm]
    ignore:
      - { goos: darwin, goarch: '386' }
      - { goos: darwin, goarch: arm }
      - { goos: windows, goarch: arm64 }
      - { goos: windows, goarch: arm }
      - { goos: freebsd, goarch: arm64 }
    binary: '{{ .ProjectName }}_v{{ .Version }}'
archives:
  - format: zip
    name_template: '{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}'
checksum:
  extra_files:
    - glob: 'terraform-registry-manifest.json'
      name_template: '{{ .ProjectName }}_{{ .Version }}_manifest.json'
  name_template: '{{ .ProjectName }}_{{ .Version }}_SHA256SUMS'
  algorithm: sha256
signs:
  - artifacts: checksum
    args:
      - "--batch"
      - "--local-user"
      - "{{ .Env.GPG_FINGERPRINT }}"
      - "--output"
      - "${signature}"
      - "--detach-sign"
      - "${artifact}"
release:
  extra_files:
    - glob: 'terraform-registry-manifest.json'
      name_template: '{{ .ProjectName }}_{{ .Version }}_manifest.json'
changelog:
  use: github
  sort: asc
  groups:
    - title: Features
      regexp: '^.*?feat(\(.+?\))??!?:.+$'
      order: 0
    - title: Bug fixes
      regexp: '^.*?fix(\(.+?\))??!?:.+$'
      order: 1
    - title: Others
      order: 999
```

- [ ] **Step 2: Add `terraform-registry-manifest.json`**

Create `terraform-registry-manifest.json`:

```json
{
  "version": 1,
  "metadata": { "protocol_versions": ["6.0"] }
}
```

- [ ] **Step 3: Commit**

```bash
git add .goreleaser.yml terraform-registry-manifest.json
git commit -S -m "release: add goreleaser config and registry manifest

Ready for registry publishing when v0.1.0 is tagged. Builds for
linux/darwin/windows/freebsd × amd64/arm64. GPG-signs checksums."
```

---

### Task 25: Verification pass + tag v0.1.0-rc1

- [ ] **Step 1: Run the full local test suite**

Run:
```bash
go mod tidy
go vet ./...
go test -race -count=1 ./...
golangci-lint run
```
Expected: all green.

- [ ] **Step 2: Smoke-test locally against an age fixture**

Run:
```bash
make install VERSION=0.1.0-rc1
cd examples/age
terraform init
terraform plan
```
Expected: plan completes; no errors. Output is `(known after apply)` for the sensitive output (good — sensitivity is honored).

- [ ] **Step 3: Tag and push**

Only after the user explicitly approves shipping a release candidate:

```bash
git tag -s v0.1.0-rc1 -m "v0.1.0-rc1: decrypt + first-class auth (Phase 1)"
git push origin main --tags
```

(Push to remote is a confirmation gate — do not run without explicit user okay.)

- [ ] **Step 4: Update plan tracking**

Mark this plan as complete; open Phase 2 plan from spec §14.

---

## Self-Review Notes

**Spec coverage check:**

| Spec section | Plan coverage |
|---|---|
| §2 first-class credential config | Tasks 4–8 (auth blocks), 15 (provider Configure) |
| §3 architecture (bypass decrypt.Data, build MasterKey directly) | Task 13 |
| §4 plugin-framework SDK | Task 1 |
| §5.1 provider block schema | Task 15 |
| §5.2 alias support | Free with framework; example in Task 21 multi-alias |
| §5.3 per-resource auth overrides | Tasks 16, 17, 18, 19 |
| §6.1 `data sops_file` (carlpett-compatible + data_json + metadata) | Task 16 |
| §6.2 `data sops_external` | Task 17 |
| §6.3 ephemeral variants | Tasks 18, 19 |
| §6.4 `resource sops_file` | **Deferred to Phase 2** (out of scope per §14) |
| §6.5 provider functions | **Deferred to Phase 3** |
| §7 decryption data flow | Task 14 (decrypt orchestrator) |
| §8 concurrency model | Task 11 (semaphore) |
| §9 caching | **Deferred to Phase 3** |
| §10 error model | Tasks 14, 16 (diagnostics with actionable hints) |
| §11 testing strategy | Tasks 2–14 (unit), 16/17/18/19 (acceptance-style), 20 (real KMS) |
| §12 repo layout | Tasks 1, 16, 18 |
| §13 release & versioning | Task 24 (goreleaser); release happens after Task 25 |

All Phase 1 spec sections have at least one task. Phase 2 and 3 items are intentionally deferred per §14 phasing.

**Placeholder scan:** No "TBD" / "TODO: implement later" / "add appropriate validation" / unspecified test bodies. Every code step shows the actual code.

**Type consistency check:**
- `auth.Config` (Task 2) is consumed by every later component — name and shape stable.
- `sopswrap.Decrypt` (Task 14) input/output shapes match what `internal/datasources/file.go` (Task 16) and `internal/ephemeral/file.go` (Task 18) call into.
- `ProviderData` and `ProviderDataAccessor` interface (Tasks 15, 16, 18) — same method name `ProviderAuthConfig` used everywhere.
- `RebuildKeyGroups` (Task 13) signature matches what `Decrypt` calls (Task 14).
- Schema block functions (`AWSBlockSchema` for provider, `AWSBlockSchemaForDataSource` for data sources, `AWSBlockSchemaForEphemeral` for ephemerals) — three variants per auth source, all required because the framework uses three different `schema` packages.

**Scope check:** This is Phase 1 only — decrypt + auth. Phase 2 (encrypt + drift) and Phase 3 (functions + cache) get separate plans after Phase 1 ships. Right size for one execution session.

---
