# terraform-provider-sops

[![CI](https://github.com/elioetibr/terraform-provider-sops/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/elioetibr/terraform-provider-sops/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/elioetibr/terraform-provider-sops/branch/main/graph/badge.svg)](https://codecov.io/gh/elioetibr/terraform-provider-sops)
[![Go Report Card](https://goreportcard.com/badge/github.com/elioetibr/terraform-provider-sops)](https://goreportcard.com/report/github.com/elioetibr/terraform-provider-sops)
[![Go Reference](https://pkg.go.dev/badge/github.com/elioetibr/terraform-provider-sops.svg)](https://pkg.go.dev/github.com/elioetibr/terraform-provider-sops)
[![Release](https://img.shields.io/github/v/release/elioetibr/terraform-provider-sops?display_name=tag&sort=semver)](https://github.com/elioetibr/terraform-provider-sops/releases)
[![Go version](https://img.shields.io/github/go-mod/go-version/elioetibr/terraform-provider-sops)](go.mod)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](LICENSE)

A Terraform provider for [SOPS](https://getsops.io/) — encrypt and decrypt files at plan time without exporting `AWS_PROFILE=…` to your shell.

**Key advantages over `carlpett/terraform-provider-sops`:**

- Configure AWS / GCP / Azure / age / PGP credentials **on the provider block** or per data source. No more `AWS_PROFILE=production terraform apply`.
- Cross-account KMS via `assume_role` override per resource.
- Provider `alias` for multi-environment setups.
- Structured nested output (`data_json`) in addition to the flat `data` map.
- Audit `metadata` attribute (lastmodified, MAC, KMS ARNs).
- Concurrency-safe (fixes carlpett #126 — random failures with ≥7 parallel decrypts).
- Ephemeral resources for zero-state-leakage decryption.
- **Managed `sops_file` resource** for write-side encryption with drift detection and key rotation (Phase 2).

## Quick start

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

## Encrypting files (Phase 2)

The `sops_file` resource encrypts plaintext to a SOPS file on disk. Plaintext is passed via the write-only `content_wo` attribute — it never lands in state. Bumping `content_wo_version` re-encrypts:

```hcl
resource "sops_file" "app" {
  path               = "${path.module}/secrets.enc.yaml"
  content_wo         = file("${path.module}/plaintext.yaml")
  content_wo_version = "1"
  input_type         = "yaml"

  creation_rules {
    age_recipients = ["age1qpf4q3wxc5m9eu3a7kp7z82l49yn94zd7r6c3qpf3v66h8x35y7sz4jqlf"]
  }
}
```

Out-of-band edits to the file are detected on `terraform plan` via a SHA-256 of the decrypted plaintext (`plaintext_sha256` in state).

Rotate master keys without re-encrypting plaintext by adding/removing recipients (or KMS ARNs) and flipping `rotate_keys = true` for a single apply:

```hcl
  creation_rules {
    age_recipients = ["age1...old", "age1...new"]
  }
  rotate_keys = true
```

> Requires Terraform **>= 1.11** (write-only attribute support).

## Migrating from `carlpett/sops`

The data source attributes (`source_file`, `input_type`, `data`, `raw`) match 1:1. In most cases the migration is a one-line change to your `required_providers` block:

```diff
 terraform {
   required_providers {
     sops = {
-      source = "carlpett/sops"
+      source = "elioetibr/sops"
     }
   }
 }
```

…and then you can delete `AWS_PROFILE=…` from your wrapper script and put it on the provider block instead.

## Examples

See `examples/` for: AWS profile, cross-account, age, multi-alias, and `encrypt-resource` (managed `sops_file`) setups.

## Running the test suite

```bash
make test          # unit tests
make testacc       # cloud acceptance tests (requires TF_ACC=1 + cloud creds)
```

## Running cloud acceptance tests

AWS KMS:

```bash
export TF_ACC=1
export SOPS_TEST_AWS_PROFILE=production-sre
export SOPS_TEST_KMS_ARN=arn:aws:kms:us-east-1:123:key/abc
go test -tags=acceptance ./internal/sopswrap/...
```

## Status

**Phase 1 (v0.1.x):** decrypt + per-call credential injection. Shipped.

**Phase 2 (v0.2.x):** `sops_file` write resource + drift detection + key rotation. Shipped.

**Phase 3 (v0.3.x):** provider functions + LRU cache + Vault. Planned.

See `docs/superpowers/specs/2026-05-14-terraform-sops-provider-design.md` for the full design.

## License

MIT.
