# terraform-provider-sops (elioetibr/sops) — Design Spec

**Date:** 2026-05-14
**Author:** Elio S. Jr.
**Status:** Draft — pending review
**Replaces:** intended as a feature-superset of `carlpett/terraform-provider-sops`

---

## 1. Motivation

`carlpett/terraform-provider-sops` is the de-facto SOPS provider for Terraform, but it has structural limitations that make it painful for production automation:

- **No credential configuration on the provider block.** The provider schema is empty; SOPS decryption auth must come from process environment variables (`AWS_PROFILE`, `AWS_SDK_LOAD_CONFIG`, `AWS_REGION`, `GOOGLE_APPLICATION_CREDENTIALS`, etc.). For multi-account or multi-environment Terraform runs this means callers must wrap `terraform` in `AWS_PROFILE=… terraform apply` per-environment, which is hostile to CI/CD, Terraform Cloud dynamic credentials, and any orchestration tool that runs many envs in one process.
- **No per-resource credential override.** Cross-account KMS (`provider for prod`, `data source decrypting a dev-account file`) is not expressible.
- **Decrypt-only.** No managed resource for encrypting/writing files; no key-rotation path.
- **Concurrency bug at scale** (carlpett #126): ≥7 parallel `sops_file` reads intermittently fail.
- **Flattened output** (carlpett #98): nested YAML/JSON collapses into a flat key/value map, breaking `for_each` over structured data.
- **No provider functions** (TF ≥1.8): no zero-state-leakage decryption primitive.
- **Stalled maintenance:** open PRs for resource-level env injection have sat unreviewed for months.

This provider rewrites the surface with a single goal: **production-grade SOPS in Terraform with no environment-variable gymnastics.**

## 2. Goals & non-goals

### Goals

1. First-class credential configuration at provider, alias, and per-resource level for **AWS KMS, GCP KMS, Azure Key Vault, age, PGP, and HashiCorp Vault**.
2. Full SOPS lifecycle: decrypt **and** encrypt.
3. State-leakage choice for every operation: data source, ephemeral resource, managed resource, and provider function.
4. Drop-in attribute compatibility with `carlpett/sops` so migration is a one-line provider swap.
5. Concurrency-safe (fixes #126) with optional in-memory caching.
6. Structured nested output for YAML/JSON files (fixes #98), in addition to the flat `data` map.
7. Conformance with HashiCorp's official `provider` block conventions ([Terraform provider block reference](https://developer.hashicorp.com/terraform/language/block/provider)) — provider-specific args + nested blocks only, no `version` attribute (use `required_providers`), `alias` for multi-identity setups.

### Non-goals

- Reimplementing SOPS itself (we depend on `github.com/getsops/sops/v3`).
- Supporting non-SOPS encrypted formats (Vault-only secrets, Sealed Secrets, etc.).
- A CLI. This is purely a Terraform provider.
- Sub-millisecond performance. Correctness and ergonomics first.

## 3. High-level architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  terraform-provider-sops                        │
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────────────────────┐     │
│  │ provider block  │    │   data / ephemeral / resource / │     │
│  │  + alias        │───▶│   function entry points         │     │
│  │  + auth blocks  │    └──────────────┬──────────────────┘     │
│  └─────────────────┘                   │                        │
│                                        ▼                        │
│                    ┌────────────────────────────────────┐       │
│                    │   internal/provider/auth (merge)   │       │
│                    │   provider-level + per-call  ⇒ Cfg │       │
│                    └────────────────┬───────────────────┘       │
│                                     ▼                           │
│                    ┌────────────────────────────────────┐       │
│                    │   internal/sopswrap                │       │
│                    │   - load file → sops.Tree (Store)  │       │
│                    │   - build MasterKeys w/ injected   │       │
│                    │     creds (kms/gcp/azkv/age/pgp/   │       │
│                    │     vault) — bypass decrypt.Data   │       │
│                    │   - Decrypt / Encrypt              │       │
│                    │   - concurrency mutex + LRU cache  │       │
│                    └────────────────┬───────────────────┘       │
│                                     ▼                           │
│                    ┌────────────────────────────────────┐       │
│                    │   github.com/getsops/sops/v3       │       │
│                    │   (Tree, Stores, MasterKey, KS)    │       │
│                    └────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

**Critical architectural decision:** we do **not** call `decrypt.Data()` or `decrypt.File()` from the SOPS public API. Those helpers offer no per-call credential injection — the entire reason carlpett can't fix the AWS_PROFILE problem. Instead we construct master keys directly (`kms.MasterKey{Arn, Role, AwsProfile, …}`), then invoke `tree.Metadata.GetDataKeyWithKeyServices()`. The SOPS CLI uses the same pattern in `cmd/sops/encrypt.go`; this is the supported lower-level API.

## 4. SDK choice

**`terraform-plugin-framework`** (current HashiCorp recommendation for new providers), targeting Terraform ≥1.8 for provider functions and ≥1.11 for ephemeral resources. No SDKv2 / no `terraform-plugin-mux` — greenfield codebase, no legacy to bridge.

## 5. Provider block schema

Conforms to the [official `provider` block reference](https://developer.hashicorp.com/terraform/language/block/provider): provider-specific arguments + nested blocks. `version` is set via `required_providers` (not in the provider block); `alias` is the standard meta-argument and is used for multi-identity setups.

### 5.1 Full schema

```hcl
terraform {
  required_providers {
    sops = {
      source  = "elioetibr/sops"
      version = ">= 0.1.0"
    }
  }
}

provider "sops" {
  # ───── AWS KMS auth ─────
  aws {
    profile                  = "production-sre"
    region                   = "us-east-1"
    shared_config_files      = ["~/.aws/config"]
    shared_credentials_files = ["~/.aws/credentials"]

    # process-scoped env injection (does NOT pollute the parent process)
    env = {
      AWS_SDK_LOAD_CONFIG = "1"
    }

    assume_role {
      role_arn     = "arn:aws:iam::123456789012:role/sops-reader"
      session_name = "terraform-sops"
      external_id  = "optional-external-id"
      duration     = "1h"
    }
  }

  # ───── GCP KMS auth ─────
  gcp {
    credentials_file            = "/path/to/sa.json"   # or `credentials = jsonencode(...)`
    impersonate_service_account = "sops@project.iam.gserviceaccount.com"
    quota_project               = "my-billing-project"
  }

  # ───── Azure Key Vault auth ─────
  azure {
    tenant_id              = "00000000-0000-0000-0000-000000000000"
    client_id              = "00000000-0000-0000-0000-000000000000"
    client_secret          = var.azure_client_secret     # write-only, never logged
    use_msi                = false
    use_oidc               = true   # GitHub Actions, Terraform Cloud dynamic creds
    use_workload_identity  = false
    use_cli                = false
  }

  # ───── age ─────
  age {
    key          = var.age_key            # explicit private key
    key_file     = "~/.config/sops/age/keys.txt"
    key_command  = "pass show age/sops"   # output captured into the key buffer
    ssh_private_key_file = "~/.ssh/id_ed25519"
  }

  # ───── PGP ─────
  pgp {
    gnupg_home = "~/.gnupg"
  }

  # ───── HashiCorp Vault (transit) — ships in Phase 3, shown here for the full schema picture ─────
  vault {
    address    = "https://vault.example.com"
    token      = var.vault_token
    namespace  = "engineering"
  }

  # ───── Behavior ─────
  concurrency_limit  = 4               # bounds parallel decrypts; mitigates #126
  cache_decrypted    = true            # process-memory LRU only; never written to disk
  cache_ttl          = "5m"
  decryption_order   = ["age", "kms"]  # mirrors SOPS_DECRYPTION_ORDER

  # ───── Key service (optional remote keyservice) ─────
  keyservice {
    socket       = "unix:///tmp/sops.sock"
    enable_local = true   # falls back to in-process if remote unavailable
  }
}
```

### 5.2 Multi-identity via `alias` (idiomatic)

```hcl
provider "sops" {
  alias = "prod"
  aws { profile = "production-sre"; region = "us-east-1" }
}

provider "sops" {
  alias = "dev"
  aws { profile = "test-sre";       region = "us-east-1" }
}

data "sops_file" "prod_secrets" {
  provider    = sops.prod
  source_file = "prod/secrets.yaml"
}
```

This is the **preferred** pattern for "different identity per environment." Per-resource overrides (§6) exist for "different identity per file within the same environment" (e.g., cross-account KMS).

### 5.3 Per-resource overrides

Every data source, resource, ephemeral, and function accepts the same `aws { … }` / `gcp { … }` / `azure { … }` / `age { … }` / `pgp { … }` / `vault { … }` blocks. Merge semantics:

1. Start with provider-block config (possibly via `alias`).
2. Overlay per-resource config — any field set on the per-resource block replaces the provider-block value for **this call only**.
3. Build `MasterKey`s with the merged config.

The merge is shallow on the leaf-field level — there is no list-append for `shared_config_files`; per-resource value wins outright. This matches user mental model and matches how the AWS provider does `assume_role`.

## 6. Components

### 6.1 `data "sops_file"` (carlpett-compatible)

```hcl
data "sops_file" "secrets" {
  source_file = "secrets.yaml"
  input_type  = "yaml"          # yaml | json | dotenv | ini | binary | raw

  # optional per-call auth override
  aws { profile = "different-account" }
}

# Outputs
output "raw"       { value = data.sops_file.secrets.raw       }   # plaintext bytes as string
output "flat"      { value = data.sops_file.secrets.data      }   # flat map[string]string (carlpett-compat)
output "nested"    { value = jsondecode(data.sops_file.secrets.data_json) }   # NEW — structured
output "metadata"  { value = data.sops_file.secrets.metadata  }   # NEW — lastmodified, mac, version, kms_arns
```

| attribute     | type                           | notes                                                                                                       |
| ------------- | ------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| `source_file` | string (required)              | path to encrypted file                                                                                      |
| `input_type`  | string (optional)              | one of yaml/json/dotenv/ini/binary/raw; auto-detected from extension if omitted                             |
| `data`        | map(string)                    | **flat** key/value (carlpett-compatible). Nested keys joined with `.`                                       |
| `data_json`   | string                         | **NEW.** Structured JSON of the decrypted tree                                                              |
| `raw`         | string                         | decrypted file bytes                                                                                        |
| `metadata`    | object                         | `{ lastmodified, mac, version, key_groups, kms_arns, gcp_kms, azure_kv, age_recipients, pgp_fingerprints }` |
| `ignore_mac`  | bool (optional, default false) | with deprecation-style warning on every plan when true                                                      |

### 6.2 `data "sops_external"` (carlpett-compatible)

```hcl
data "sops_external" "from_string" {
  source     = var.encrypted_yaml_blob
  input_type = "yaml"
}
```

Same outputs as `sops_file`.

### 6.3 `ephemeral "sops_file"` / `ephemeral "sops_external"`

Identical schema to the data sources. Use when plaintext must never enter state. Available on TF ≥1.11.

### 6.4 `resource "sops_file"` (NEW — encrypt + drift)

```hcl
resource "sops_file" "secrets" {
  path        = "secrets.yaml"
  format      = "yaml"          # required for resources (no extension inference)
  content_wo  = var.plaintext   # write-only attribute — never stored in plan or state
  content_wo_version = 1        # bumping this triggers re-encrypt

  creation_rules {
    kms_arns           = ["arn:aws:kms:us-east-1:123:key/abc"]
    age_recipients     = ["age1..."]
    pgp_fingerprints   = []
    encrypted_regex    = "^(data|stringData)$"   # or `encrypted_suffix`, `unencrypted_regex`, `unencrypted_suffix`
  }

  aws { profile = "production-sre" }
}
```

| concern              | behavior                                                                                                                                        |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `Create`             | encrypt `content_wo` to `path`.                                                                                                                 |
| `Read`               | decrypt `path`, hash plaintext + capture metadata. **Drift** = file MAC differs OR metadata changed out-of-band.                                |
| `Update`             | re-encrypt only if `content_wo_version` advanced OR `creation_rules.*` changed.                                                                 |
| `Delete`             | optional `lifecycle.prevent_destroy_file = true` to keep the file on disk after the resource is destroyed (audit safety).                       |
| `rotate_keys = true` | explicit flag triggers `sops updatekeys`-equivalent without re-encrypting plaintext.                                                            |
| Plaintext leakage    | `content_wo` is a **write-only attribute** (framework feature). Never serialized to plan or state. The only stored derivative is a sha256 hash. |
| MAC                  | always recomputed on encrypt; verified on decrypt; failure is an error unless `ignore_mac = true`.                                              |

### 6.5 Provider functions (TF ≥1.8 — zero state leakage)

```hcl
locals {
  decrypted    = provider::sops::decrypt(var.ciphertext, "yaml")
  decrypted_fn = provider::sops::decrypt_file("secrets.yaml", "yaml")
  encrypted    = provider::sops::encrypt(
    jsonencode({ password = "hunter2" }),
    "json",
    { kms_arns = ["arn:aws:kms:..."] }
  )
}
```

Functions always use the provider-block config of the **default** (unaliased) `sops` provider instance — by design, to keep function call sites terse and side-effect-free. Users needing per-call credential overrides should use data sources, ephemerals, or aliased providers (functions are also addressable via alias: `provider::sops::decrypt.prod(...)`).

## 7. The decryption path (data flow)

```
data "sops_file" "x" { source_file = "s.yaml"; aws { profile = "p" } }
   │
   ▼  (framework Read)
sopswrap.Decrypt(ctx, "s.yaml", mergedOpts)
   │
   ├─ semaphore.Acquire(provider.concurrency_limit)        # fixes #126
   ├─ cache.Get(path, mtime, sha256) → hit? return         # optional
   │
   ├─ store := store.For("yaml")                            # yaml/json/dotenv/ini/binary
   ├─ encryptedTree, err := store.LoadEncryptedFile(bytes)
   │
   ├─ masterKeys := masterkey.Build(
   │     tree.Metadata,
   │     mergedOpts.AWS,   // profile, region, role_arn, env
   │     mergedOpts.GCP,   // credentials, impersonate_sa
   │     mergedOpts.Azure, // tenant, client, msi/oidc
   │     mergedOpts.Age,   // key, key_file, key_command, ssh
   │     mergedOpts.PGP,
   │     mergedOpts.Vault,
   │  )
   │     └─ for each KMS key in tree.Metadata.KeyGroups:
   │           kms.MasterKey{
   │              Arn:                 metadataArn,
   │              Role:                opts.AWS.AssumeRole.RoleArn,
   │              AwsProfile:          opts.AWS.Profile,
   │              EncryptionContext:   metadataCtx,
   │           }
   │           └─ session built with opts.AWS.SharedConfigFiles etc.
   │
   ├─ keyservices := keyservice.Resolve(opts.KeyService)   # local + optional remote
   ├─ dataKey, err := tree.Metadata.GetDataKeyWithKeyServices(keyservices)
   ├─ err := tree.Decrypt(dataKey, cipher)
   │
   ├─ plaintextBytes := store.EmitPlainFile(tree)
   ├─ flatMap := flatten(tree)                              # carlpett-compat
   ├─ nestedJSON := json.Marshal(tree)                      # NEW
   │
   └─ cache.Put(...); semaphore.Release(); return
```

## 8. Concurrency model

- A package-level `golang.org/x/sync/semaphore.Weighted` bounded by `provider.concurrency_limit` (default 4) wraps every `Decrypt`/`Encrypt` call.
- GCP and Azure clients are constructed **per call** (not memoized globally) when per-call auth is in play — Google's `google.DefaultTokenSource` caches globally and would defeat per-resource credentials.
- AWS sessions are built fresh per call with the merged `aws.Config`; the SDK's own credential cache lives on the session, so freshness is correct.
- GPG agent serialization: the `pgp.MasterKey` path goes through `gpg --decrypt` shelling out; serialize PGP calls behind a separate mutex to avoid agent contention.

## 9. Caching

- Optional, default **on** (`cache_decrypted = true`).
- Key: `sha256(path) || mtime_ns || filesize`. If any change → cache miss.
- LRU sized to 256 entries by default; configurable (`cache_max_entries`).
- TTL: `cache_ttl` (default `5m`). Past TTL → forced re-decrypt.
- Process-memory only; **never** written to disk. Documented.
- Cache is per-provider-instance — aliased providers do not share entries (avoids accidental cross-identity hits).

## 10. Error model

Distinct Go error types surfaced as Terraform diagnostics with summaries + actionable details:

| error               | detail surfaced                                                                                                                         |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `ErrAuth`           | "AWS KMS access denied for `arn:aws:kms:...` — check `provider \"sops\" { aws { profile = ... } }` or per-resource `aws { ... }` block" |
| `ErrKeyService`     | "remote keyservice at `unix:///tmp/sops.sock` unreachable — set `keyservice.enable_local = true` to fall back"                          |
| `ErrMAC`            | "MAC mismatch on `secrets.yaml` — file may have been tampered with. Set `ignore_mac = true` only as a last resort"                      |
| `ErrFormat`         | "could not parse `secrets.yaml` as `yaml` — try `input_type = \"binary\"` or check extension/contents"                                  |
| `ErrPartialDecrypt` | "1 of 2 key groups failed; threshold met. Failing keys: …" — only fatal if threshold unmet                                              |

All errors **never** include plaintext fragments.

## 11. Testing strategy

- **Unit tests:** mock the `keyservice.KeyServiceClient` interface; verify credential plumbing into `MasterKey` structs (the AWS_PROFILE problem) without hitting cloud.
- **Acceptance tests** (build-tag `acceptance`, run only in CI with creds):
  - `acc_aws_kms_test.go` — real KMS in a sandbox AWS account, profile and assume-role paths.
  - `acc_gcp_kms_test.go` — real GCP KMS via service-account-impersonation.
  - `acc_azure_kv_test.go` — real Azure Key Vault via OIDC.
  - `acc_age_test.go`, `acc_pgp_test.go`, `acc_vault_test.go` — local key fixtures.
- **Concurrency regression** (`concurrency_test.go`): spin 32 parallel decrypts against age-encrypted fixtures, assert zero failures. Without our semaphore + per-call client construction this reproduces carlpett #126.
- **Drift detection:** tamper-with-encrypted-file test for the resource path.
- **Format coverage:** yaml/json/dotenv/ini/binary/raw fixtures, each with nested + flat shapes.
- **Plaintext leakage:** assert state JSON never contains plaintext substrings for resource + ephemeral paths.
- **Documentation generated** via `tfplugindocs`; CI checks generated docs match committed.

## 12. Repository layout

```
terraform-provider-sops/
├── main.go
├── go.mod                                      # github.com/elioetibr/terraform-provider-sops
├── internal/
│   ├── provider/
│   │   ├── provider.go                         # New(), Schema, Configure
│   │   ├── provider_test.go
│   │   └── auth/
│   │       ├── aws.go        aws_test.go
│   │       ├── gcp.go        gcp_test.go
│   │       ├── azure.go      azure_test.go
│   │       ├── age.go        age_test.go
│   │       ├── pgp.go        pgp_test.go
│   │       ├── vault.go      vault_test.go
│   │       ├── merge.go      merge_test.go
│   │       └── envinject.go  envinject_test.go
│   ├── sopswrap/
│   │   ├── decrypt.go        decrypt_test.go
│   │   ├── encrypt.go        encrypt_test.go   # phase 2
│   │   ├── store.go          store_test.go
│   │   ├── masterkey.go      masterkey_test.go
│   │   ├── keyservice.go
│   │   ├── concurrency.go    concurrency_test.go
│   │   └── cache.go          cache_test.go
│   ├── datasources/
│   │   ├── file.go           file_test.go
│   │   └── external.go       external_test.go
│   ├── ephemeral/
│   │   ├── file.go
│   │   └── external.go
│   ├── resources/                              # phase 2
│   │   └── file.go
│   └── functions/                              # phase 3
│       ├── decrypt.go
│       ├── decrypt_file.go
│       └── encrypt.go
├── examples/
│   ├── aws-kms-profile/
│   ├── aws-cross-account/
│   ├── gcp-impersonation/
│   ├── azure-oidc/
│   ├── age/
│   ├── multi-alias/
│   └── encrypt-resource/                       # phase 2
├── docs/                                       # tfplugindocs output
├── docs/superpowers/specs/                     # this file
└── .github/
    ├── workflows/
    │   ├── ci.yml                              # unit + lint
    │   ├── acceptance.yml                      # gated on tag/manual dispatch
    │   └── release.yml                         # goreleaser → registry
    └── PULL_REQUEST_TEMPLATE.md
```

## 13. Release & versioning

- **v0.1.0** — Phase 1 scope (see §14). Compatible with carlpett `sops_file` / `sops_external` attribute shapes for one-line migration.
- **v0.2.0** — Phase 2 (encrypt resource).
- **v0.3.0** — Phase 3 (functions, structured caching, key rotation, vault).
- **v1.0.0** — when external users have run against v0.x for ≥3 months with no breaking schema feedback.

Registry: `registry.terraform.io/elioetibr/sops`. Build + sign via `goreleaser`; provider signing key per [HashiCorp publishing docs](https://developer.hashicorp.com/terraform/registry/providers/publishing). MIT licensed (matches existing LICENSE in repo).

## 14. Phasing

### Phase 1 — Decrypt MVP with auth fix (v0.1.0)

- Provider block: full `aws { … }` (incl. `assume_role`), `gcp { … }`, `azure { … }`, `age { … }`, `pgp { … }`. Vault held to Phase 3.
- Provider `alias` support (free with framework).
- `data "sops_file"` + `data "sops_external"`.
- `ephemeral "sops_file"` + `ephemeral "sops_external"`.
- Per-resource auth overrides (merge semantics from §5.3).
- Concurrency semaphore (default 4); no cache yet.
- Flat `data` map (carlpett-compat) + structured `data_json` + `metadata` attribute.
- Formats: yaml/json/dotenv/ini/binary/raw.
- Unit tests + AWS-KMS acceptance test on CI.
- Migration guide in README.

### Phase 2 — Encrypt + drift (v0.2.0)

- `resource "sops_file"` with write-only `content_wo` + `content_wo_version`.
- Drift detection on file MAC + metadata.
- `creation_rules` block honoring `encrypted_regex`/`unencrypted_suffix`/etc.
- `rotate_keys = true` `updatekeys`-equivalent path.
- Acceptance tests: round-trip encrypt → decrypt → tamper → drift.

### Phase 3 — Functions + advanced (v0.3.0)

- `provider::sops::decrypt`, `decrypt_file`, `encrypt`.
- In-memory LRU cache.
- `vault { … }` HashiCorp Vault transit support.
- Remote `keyservice` socket support.
- GCP impersonation + Azure workload identity hardening.
- Documentation polish, examples expansion.

## 15. Risks & mitigations

| risk                                                                     | mitigation                                                                                                                                                        |
| ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SOPS lower-level API changes between minor versions                      | Pin `getsops/sops/v3` to a single minor in go.mod; integration-test on each bump.                                                                                 |
| Plaintext leaks via diagnostics or logs                                  | Centralize all error formatting in one package; unit-test that no plaintext flows through; redact `data`/`raw` from any debug logging by default.                 |
| `content_wo` write-only attributes are still relatively new in framework | Acceptance-test against the lowest-supported TF version (1.11) on each release; document a fallback pattern using ephemeral + `local_file` for users on older TF. |
| Concurrency semaphore could become a bottleneck on giant Terraform plans | Default 4, configurable up to 64; document tuning.                                                                                                                |
| Cross-account assume-role token expiry mid-plan                          | Refresh credentials on every Decrypt call (no global session memoization for cross-account paths).                                                                |
| Cache hits returning stale plaintext after file edited out-of-band       | Cache key includes mtime + size; TTL bounds the worst case; cache is opt-out.                                                                                     |

## 16. Open questions (none blocking)

- **Telemetry?** Probably no — secrets tooling shouldn't phone home. Keep zero by default.
- **Sentinel/CEL integration for `creation_rules`?** Not in Phase 2; revisit after user demand.
- **`.sops.yaml` discovery?** Inherit SOPS's existing behavior (walk up from CWD); document that provider-block `creation_rules` overrides `.sops.yaml`.

## 17. References

- SOPS Go library: <https://pkg.go.dev/github.com/getsops/sops/v3>
- SOPS docs: <https://getsops.io/docs/>
- Terraform `provider` block reference: <https://developer.hashicorp.com/terraform/language/block/provider>
- Terraform Plugin Framework: <https://developer.hashicorp.com/terraform/plugin/framework>
- Write-only attributes: <https://developer.hashicorp.com/terraform/plugin/framework/resources/write-only-attributes>
- Provider functions: <https://developer.hashicorp.com/terraform/plugin/framework/functions>
- Ephemeral resources: <https://developer.hashicorp.com/terraform/plugin/framework/ephemeral-resources>
- carlpett provider: <https://github.com/carlpett/terraform-provider-sops>
- Key carlpett issues fixed: #45, #89, #98, #112, #119, #126, #146

---

**Next step:** invoke `superpowers:writing-plans` to produce the Phase 1 implementation plan after this design is approved.
