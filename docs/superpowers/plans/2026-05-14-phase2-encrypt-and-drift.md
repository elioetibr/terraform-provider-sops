# terraform-provider-sops — Phase 2 (Encrypt + Drift) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `elioetibr/sops` v0.2.0 — add a `resource "sops_file"` that encrypts plaintext to disk with write-only `content_wo`, MAC-based drift detection on `Read`, and `rotate_keys = true` for key rotation without re-encrypting plaintext.

**Architecture:** Mirror the Phase 1 decrypt path: bypass any high-level SOPS helper, construct fresh `MasterKey` instances per `creation_rules` with injected credentials, call `tree.GenerateDataKeyWithKeyServices()` + `tree.Encrypt(key, cipher)`, and emit via the same `Store` dispatcher. Drift detection compares a sha256 of the decrypted plaintext (stored in state alongside SOPS metadata) against the live file's decrypted-plaintext hash. Key rotation re-encrypts only the data key, never the file's plaintext.

**Tech Stack:** Same as Phase 1 — `github.com/hashicorp/terraform-plugin-framework` v1.19, `github.com/getsops/sops/v3` v3.13, write-only attributes (TF ≥1.11). One small addition: `crypto/sha256` for the plaintext digest used in drift comparison.

**Reference spec:** `docs/superpowers/specs/2026-05-14-terraform-sops-provider-design.md` §6.4, §11, §14 (Phase 2 row).

---

## File Structure

Created in this plan (Phase 2 only):

```
internal/
├── provider/auth/
│   ├── creation_rules.go               # NEW — CreationRulesModel + ToConfig + 2 schema variants
│   └── creation_rules_test.go          # NEW
├── sopswrap/
│   ├── encrypt.go                      # NEW — Encrypt(ctx, EncryptInput) (*EncryptResult, error)
│   ├── encrypt_test.go                 # NEW
│   ├── updatekeys.go                   # NEW — UpdateKeys(ctx, ...) for key rotation
│   ├── updatekeys_test.go              # NEW
│   ├── newmasterkey.go                 # NEW — BuildMasterKeysFromRules(rules, cfg) []sops.KeyGroup
│   └── newmasterkey_test.go            # NEW
└── resources/                           # NEW package
    ├── file.go                          # NEW — sops_file managed resource
    ├── file_test.go                     # NEW
    ├── drift.go                         # NEW — hash + drift helpers
    └── drift_test.go                    # NEW
examples/
└── encrypt-resource/                    # NEW
    └── main.tf
```

Modified:

- `internal/provider/provider.go` — register `resources.NewFileResource`
- `README.md` — short paragraph in the "Status" section moving Phase 2 from "Planned" to "Shipped"

## Conventions

- **Every commit GPG-signed** (`git commit -S`). NO `Co-Authored-By` trailers ever. Hard rules from `~/.claude/CLAUDE.md`.
- Module path: `github.com/elioetibr/terraform-provider-sops`.
- Go style: prefer interfaces for testability, SOLID/DRY/KISS, files ≤300 lines, functions ≤30 lines where reasonable.
- **TDD discipline:** every implementation task is *failing test → run → fail → implement → run → pass → commit*.
- Test files use `package <pkg>_test` (external test package) unless they need package-internal access.

---

### Task 1: `auth.CreationRules` type + Model + 2 schema variants

The data type that says "encrypt this file with these keys, using these regex/suffix rules." Lives alongside the AWS/GCP/Azure/age/PGP auth models.

**Files:**
- Create: `internal/provider/auth/creation_rules.go`
- Create: `internal/provider/auth/creation_rules_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/provider/auth/creation_rules_test.go`:

```go
package auth_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

func TestCreationRulesToConfig_AllFields(t *testing.T) {
	t.Parallel()
	m := &auth.CreationRulesModel{
		KMSARNs:          listOf(t, "arn:aws:kms:us-east-1:1:key/abc"),
		GCPKMSResources:  listOf(t, "projects/p/locations/global/keyRings/r/cryptoKeys/k"),
		AzureKVKeys:      listOf(t, "https://kv.vault.azure.net/keys/k/v"),
		AgeRecipients:    listOf(t, "age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"),
		PGPFingerprints:  listOf(t, "FBC7B9E2A4F9289AC0C1D4843D16CEE4A27381B4"),
		EncryptedRegex:   types.StringValue("^(data|stringData)$"),
		UnencryptedRegex: types.StringValue(""),
		EncryptedSuffix:  types.StringValue(""),
		UnencryptedSuffix: types.StringValue("_unencrypted"),
		Threshold:        types.Int64Value(2),
	}
	cfg, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError(), diags.Errors())
	require.Equal(t, []string{"arn:aws:kms:us-east-1:1:key/abc"}, cfg.KMSARNs)
	require.Equal(t, []string{"age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"}, cfg.AgeRecipients)
	require.Equal(t, "^(data|stringData)$", cfg.EncryptedRegex)
	require.Equal(t, "_unencrypted", cfg.UnencryptedSuffix)
	require.Equal(t, 2, cfg.Threshold)
}

func TestCreationRulesToConfig_NilSafe(t *testing.T) {
	t.Parallel()
	var m *auth.CreationRulesModel
	cfg, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError())
	require.Empty(t, cfg.KMSARNs)
	require.Empty(t, cfg.AgeRecipients)
}

func TestCreationRulesToConfig_RequireAtLeastOneKey(t *testing.T) {
	t.Parallel()
	// Empty creation_rules with no keys at all is a user error.
	m := &auth.CreationRulesModel{}
	_, diags := m.ToConfig(context.Background())
	require.True(t, diags.HasError(),
		"creation_rules with no kms_arns/age_recipients/etc. must error")
}

// helper local to this test file
func listOf(t *testing.T, ss ...string) types.List {
	t.Helper()
	vals := make([]attr.Value, len(ss))
	for i, s := range ss {
		vals[i] = types.StringValue(s)
	}
	l, diags := types.ListValue(types.StringType, vals)
	require.False(t, diags.HasError(), diags.Errors())
	return l
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/provider/auth/... -run TestCreationRules`
Expected: FAIL with `undefined: auth.CreationRulesModel`.

- [ ] **Step 3: Implement `creation_rules.go`**

Create `internal/provider/auth/creation_rules.go`:

```go
package auth

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	provschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

// CreationRules holds the master-key list and content-rules a new sops file is
// encrypted with. Consumed by sopswrap.Encrypt.
type CreationRules struct {
	KMSARNs           []string
	GCPKMSResources   []string
	AzureKVKeys       []string
	AgeRecipients     []string
	PGPFingerprints   []string
	EncryptedRegex    string
	UnencryptedRegex  string
	EncryptedSuffix   string
	UnencryptedSuffix string
	Threshold         int
}

// HasAnyKey returns whether at least one key source is configured.
func (c CreationRules) HasAnyKey() bool {
	return len(c.KMSARNs) > 0 || len(c.GCPKMSResources) > 0 ||
		len(c.AzureKVKeys) > 0 || len(c.AgeRecipients) > 0 ||
		len(c.PGPFingerprints) > 0
}

// CreationRulesModel is the terraform-plugin-framework data model.
type CreationRulesModel struct {
	KMSARNs           types.List   `tfsdk:"kms_arns"`
	GCPKMSResources   types.List   `tfsdk:"gcp_kms_resources"`
	AzureKVKeys       types.List   `tfsdk:"azure_kv_keys"`
	AgeRecipients     types.List   `tfsdk:"age_recipients"`
	PGPFingerprints   types.List   `tfsdk:"pgp_fingerprints"`
	EncryptedRegex    types.String `tfsdk:"encrypted_regex"`
	UnencryptedRegex  types.String `tfsdk:"unencrypted_regex"`
	EncryptedSuffix   types.String `tfsdk:"encrypted_suffix"`
	UnencryptedSuffix types.String `tfsdk:"unencrypted_suffix"`
	Threshold         types.Int64  `tfsdk:"threshold"`
}

// ToConfig converts the framework model into the value type sopswrap consumes.
// Errors when no key source is configured (a creation_rules block with no
// recipients can never produce an encryptable file).
func (m *CreationRulesModel) ToConfig(ctx context.Context) (CreationRules, diag.Diagnostics) {
	if m == nil {
		return CreationRules{}, nil
	}
	var diags diag.Diagnostics
	out := CreationRules{
		EncryptedRegex:    m.EncryptedRegex.ValueString(),
		UnencryptedRegex:  m.UnencryptedRegex.ValueString(),
		EncryptedSuffix:   m.EncryptedSuffix.ValueString(),
		UnencryptedSuffix: m.UnencryptedSuffix.ValueString(),
		Threshold:         int(m.Threshold.ValueInt64()),
	}
	for ptr, list := range map[*[]string]types.List{
		&out.KMSARNs:         m.KMSARNs,
		&out.GCPKMSResources: m.GCPKMSResources,
		&out.AzureKVKeys:     m.AzureKVKeys,
		&out.AgeRecipients:   m.AgeRecipients,
		&out.PGPFingerprints: m.PGPFingerprints,
	} {
		if list.IsNull() || list.IsUnknown() {
			continue
		}
		var ss []string
		diags.Append(list.ElementsAs(ctx, &ss, false)...)
		*ptr = ss
	}
	if diags.HasError() {
		return out, diags
	}
	if !out.HasAnyKey() {
		diags.AddError(
			"creation_rules requires at least one key source",
			"Set kms_arns, gcp_kms_resources, azure_kv_keys, age_recipients, or pgp_fingerprints.",
		)
	}
	return out, diags
}

// CreationRulesProviderBlockSchema is the schema for the provider-block variant
// (currently unused — kept for symmetry with other auth blocks; provider-level
// creation_rules may land in a later phase).
func CreationRulesProviderBlockSchema() provschema.Block {
	return provschema.SingleNestedBlock{
		Description: "Default creation rules for new encrypted files.",
		Attributes:  creationRulesProviderAttrs(),
	}
}

// CreationRulesResourceBlockSchema is the schema for the resource-level block.
// This is the one actually used today.
func CreationRulesResourceBlockSchema() rschema.Block {
	return rschema.SingleNestedBlock{
		Description: "Master keys + content rules used when encrypting this file.",
		Attributes: map[string]rschema.Attribute{
			"kms_arns":          rschema.ListAttribute{Optional: true, ElementType: types.StringType},
			"gcp_kms_resources": rschema.ListAttribute{Optional: true, ElementType: types.StringType},
			"azure_kv_keys":     rschema.ListAttribute{Optional: true, ElementType: types.StringType},
			"age_recipients":    rschema.ListAttribute{Optional: true, ElementType: types.StringType},
			"pgp_fingerprints":  rschema.ListAttribute{Optional: true, ElementType: types.StringType},
			"encrypted_regex":   rschema.StringAttribute{Optional: true},
			"unencrypted_regex": rschema.StringAttribute{Optional: true},
			"encrypted_suffix":  rschema.StringAttribute{Optional: true},
			"unencrypted_suffix": rschema.StringAttribute{Optional: true},
			"threshold":         rschema.Int64Attribute{Optional: true},
		},
	}
}

func creationRulesProviderAttrs() map[string]provschema.Attribute {
	return map[string]provschema.Attribute{
		"kms_arns":          provschema.ListAttribute{Optional: true, ElementType: types.StringType},
		"gcp_kms_resources": provschema.ListAttribute{Optional: true, ElementType: types.StringType},
		"azure_kv_keys":     provschema.ListAttribute{Optional: true, ElementType: types.StringType},
		"age_recipients":    provschema.ListAttribute{Optional: true, ElementType: types.StringType},
		"pgp_fingerprints":  provschema.ListAttribute{Optional: true, ElementType: types.StringType},
		"encrypted_regex":   provschema.StringAttribute{Optional: true},
		"unencrypted_regex": provschema.StringAttribute{Optional: true},
		"encrypted_suffix":  provschema.StringAttribute{Optional: true},
		"unencrypted_suffix": provschema.StringAttribute{Optional: true},
		"threshold":         provschema.Int64Attribute{Optional: true},
	}
}
```

- [ ] **Step 4: Run — expect pass**

Run: `go test ./internal/provider/auth/... -v -run TestCreationRules`
Expected: 3 PASS.

- [ ] **Step 5: Commit (GPG-signed, NO Co-Authored-By)**

```bash
git add internal/provider/auth/creation_rules.go internal/provider/auth/creation_rules_test.go
git commit -S -m "feat(auth): CreationRules type + Model + resource schema

Adds the master-key list (kms_arns / gcp_kms_resources / azure_kv_keys /
age_recipients / pgp_fingerprints) plus content rules (encrypted_regex,
unencrypted_suffix, threshold) used when encrypting a new sops file.

Validates at ToConfig() that at least one key source is configured."
```

---

### Task 2: `sopswrap.BuildMasterKeysFromRules` — construct fresh master keys

Different from Phase 1's `RebuildKeyGroups` (which reconstructs keys from an existing tree's metadata). This builds master keys **from a `CreationRules` config** for a new file, with auth.Config credentials injected.

**Files:**
- Create: `internal/sopswrap/newmasterkey.go`
- Create: `internal/sopswrap/newmasterkey_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/sopswrap/newmasterkey_test.go`:

```go
package sopswrap_test

import (
	"testing"

	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/kms"
	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

func TestBuildMasterKeysFromRules_AgeOnly(t *testing.T) {
	t.Parallel()
	rules := auth.CreationRules{
		AgeRecipients: []string{"age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"},
	}
	groups, err := sopswrap.BuildMasterKeysFromRules(rules, auth.Config{})
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Len(t, groups[0], 1)
	_, ok := groups[0][0].(*age.MasterKey)
	require.True(t, ok)
}

func TestBuildMasterKeysFromRules_KMSWithProfile(t *testing.T) {
	t.Parallel()
	rules := auth.CreationRules{
		KMSARNs: []string{"arn:aws:kms:us-east-1:123:key/abc"},
	}
	cfg := auth.Config{
		AWS: auth.AWSConfig{Profile: "production-sre"},
	}
	groups, err := sopswrap.BuildMasterKeysFromRules(rules, cfg)
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Len(t, groups[0], 1)
	k, ok := groups[0][0].(*kms.MasterKey)
	require.True(t, ok)
	require.Equal(t, "arn:aws:kms:us-east-1:123:key/abc", k.Arn)
	require.Equal(t, "production-sre", k.AwsProfile,
		"AWS profile must be injected from auth.Config (the headline feature)")
}

func TestBuildMasterKeysFromRules_KMSWithAssumeRole(t *testing.T) {
	t.Parallel()
	rules := auth.CreationRules{
		KMSARNs: []string{"arn:aws:kms:us-east-1:123:key/abc"},
	}
	cfg := auth.Config{
		AWS: auth.AWSConfig{
			Profile:    "production-sre",
			AssumeRole: &auth.AWSAssumeRole{RoleARN: "arn:aws:iam::123:role/sops-writer"},
		},
	}
	groups, err := sopswrap.BuildMasterKeysFromRules(rules, cfg)
	require.NoError(t, err)
	k := groups[0][0].(*kms.MasterKey)
	require.Equal(t, "arn:aws:iam::123:role/sops-writer", k.Role)
	require.Equal(t, "production-sre", k.AwsProfile)
}

func TestBuildMasterKeysFromRules_Empty(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.BuildMasterKeysFromRules(auth.CreationRules{}, auth.Config{})
	require.Error(t, err, "empty rules must error")
}

func TestBuildMasterKeysFromRules_MixedSources(t *testing.T) {
	t.Parallel()
	// All recipients land in ONE key group. Threshold semantics live on the group.
	rules := auth.CreationRules{
		KMSARNs:       []string{"arn:aws:kms:us-east-1:1:key/a"},
		AgeRecipients: []string{"age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"},
	}
	groups, err := sopswrap.BuildMasterKeysFromRules(rules, auth.Config{})
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Len(t, groups[0], 2, "kms + age in the same group")
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/sopswrap/... -run TestBuildMasterKeysFromRules`
Expected: FAIL with `undefined: sopswrap.BuildMasterKeysFromRules`.

- [ ] **Step 3: Implement `newmasterkey.go`**

Create `internal/sopswrap/newmasterkey.go`:

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

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

// BuildMasterKeysFromRules constructs a single KeyGroup containing one MasterKey
// per recipient in the rules. Credentials from cfg are injected into KMS keys
// (the AWS_PROFILE fix); other key types get their config via scoped env vars
// at Encrypt() call time.
//
// All recipients land in one group on purpose: SOPS' threshold semantics
// operate within a group, and a typical sops file lists "any one of these
// recipients can decrypt" — that's the single-group case. Multi-group
// (M-of-N) is out of scope for Phase 2.
func BuildMasterKeysFromRules(rules auth.CreationRules, cfg auth.Config) ([]sops.KeyGroup, error) {
	if !rules.HasAnyKey() {
		return nil, fmt.Errorf("sopswrap: creation_rules has no recipients")
	}
	group := make(sops.KeyGroup, 0, 8)

	for _, arn := range rules.KMSARNs {
		role := ""
		if cfg.AWS.AssumeRole != nil {
			role = cfg.AWS.AssumeRole.RoleARN
		}
		k := kms.NewMasterKeyWithProfile(arn, role, nil, cfg.AWS.Profile)
		group = append(group, k)
	}
	for _, resID := range rules.GCPKMSResources {
		group = append(group, gcpkms.NewMasterKeyFromResourceID(resID))
	}
	for _, url := range rules.AzureKVKeys {
		// Azure KV URL convention: https://<vault>.vault.azure.net/keys/<name>/<version>
		// SOPS's azkv constructor takes vault URL + name + version, but also accepts
		// a single URL via NewMasterKeyFromURL.
		k, err := azkv.NewMasterKeyFromURL(url)
		if err != nil {
			return nil, fmt.Errorf("azkv parse %q: %w", url, err)
		}
		group = append(group, k)
	}
	for _, recipient := range rules.AgeRecipients {
		k, err := age.MasterKeyFromRecipient(recipient)
		if err != nil {
			return nil, fmt.Errorf("age recipient %q: %w", recipient, err)
		}
		group = append(group, k)
	}
	for _, fp := range rules.PGPFingerprints {
		group = append(group, pgp.NewMasterKeyFromFingerprint(fp))
	}

	// keys.MasterKey is the interface; the concrete types above all satisfy it.
	_ = keys.MasterKey(nil)
	return []sops.KeyGroup{group}, nil
}
```

- [ ] **Step 4: Verify `azkv.NewMasterKeyFromURL` exists**

Run: `go doc github.com/getsops/sops/v3/azkv | grep -i NewMasterKey`

Expected: a line like `func NewMasterKeyFromURL(url string) (*MasterKey, error)`. If the symbol doesn't exist by that name, STOP and adapt — likely candidates: `NewMasterKey(vaultURL, name, version)` requiring URL parsing first. If you must adapt, use Go's `net/url` to extract the three parts from the URL and call the lower-level constructor. Do not improvise silently — note any adaptation in the commit message.

- [ ] **Step 5: Run — expect pass**

Run: `go test ./internal/sopswrap/... -v -run TestBuildMasterKeysFromRules`
Expected: 5 PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/sopswrap/newmasterkey.go internal/sopswrap/newmasterkey_test.go
git commit -S -m "feat(sopswrap): BuildMasterKeysFromRules constructs fresh master keys

Parallel to Phase 1's RebuildKeyGroups (which reconstructs from an
existing tree's metadata). This builds master keys from a fresh
CreationRules config — used by sopswrap.Encrypt for new files.

AWS profile + assume-role injection works identically to the decrypt
path; GCP/Azure/PGP creds flow via scoped env at Encrypt() time."
```

---

### Task 3: `sopswrap.Encrypt` — encrypt orchestrator

The encrypt-side of the Decrypt() function from Phase 1. Loads plaintext bytes, builds master keys, generates a data key, encrypts the tree, emits ciphertext.

**Files:**
- Create: `internal/sopswrap/encrypt.go`
- Create: `internal/sopswrap/encrypt_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/sopswrap/encrypt_test.go`:

```go
package sopswrap_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

func testAgeRecipient(t *testing.T) string {
	t.Helper()
	// Read the public key out of testdata/age-key.txt (the second '#' header line).
	b, err := os.ReadFile(absTestdata(t, "age-key.txt"))
	require.NoError(t, err)
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "# public key:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "# public key:"))
		}
	}
	t.Fatal("could not find public key in testdata/age-key.txt")
	return ""
}

func TestEncrypt_YAMLRoundTrip(t *testing.T) {
	t.Parallel()
	pub := testAgeRecipient(t)

	plain := []byte("password: hunter2\napi_key: sk-test-12345\n")

	enc, err := sopswrap.Encrypt(context.Background(), sopswrap.EncryptInput{
		Plaintext: plain,
		Format:    sopswrap.FormatYAML,
		Rules:     auth.CreationRules{AgeRecipients: []string{pub}},
		Config:    auth.Config{},
	})
	require.NoError(t, err)
	require.NotEmpty(t, enc.Ciphertext)
	require.Contains(t, string(enc.Ciphertext), "sops:",
		"encrypted file must carry sops metadata")

	// Round-trip via Decrypt — should recover the original.
	t.Setenv("SOPS_AGE_KEY_FILE", absTestdata(t, "age-key.txt"))
	res, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: enc.Ciphertext,
		Format: sopswrap.FormatYAML,
	})
	require.NoError(t, err)
	require.Equal(t, "hunter2", res.Flat["password"])
	require.Equal(t, "sk-test-12345", res.Flat["api_key"])
}

func TestEncrypt_NoKeysErrors(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.Encrypt(context.Background(), sopswrap.EncryptInput{
		Plaintext: []byte("k: v\n"),
		Format:    sopswrap.FormatYAML,
		Rules:     auth.CreationRules{},
	})
	require.Error(t, err)
}

func TestEncrypt_EncryptedRegexHonored(t *testing.T) {
	t.Parallel()
	pub := testAgeRecipient(t)
	plain := []byte("public: world\nsecret: hunter2\n")

	enc, err := sopswrap.Encrypt(context.Background(), sopswrap.EncryptInput{
		Plaintext: plain,
		Format:    sopswrap.FormatYAML,
		Rules: auth.CreationRules{
			AgeRecipients:  []string{pub},
			EncryptedRegex: "^secret$",
		},
	})
	require.NoError(t, err)
	// `public` should remain in cleartext in the encrypted output; `secret` should not.
	require.Contains(t, string(enc.Ciphertext), "public: world",
		"keys not matching encrypted_regex must remain plaintext")
	require.NotContains(t, string(enc.Ciphertext), "hunter2",
		"keys matching encrypted_regex must be encrypted")
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/sopswrap/... -run TestEncrypt`
Expected: FAIL with `undefined: sopswrap.Encrypt`.

- [ ] **Step 3: Implement `encrypt.go`**

Create `internal/sopswrap/encrypt.go`:

```go
package sopswrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	sops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/version"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

// EncryptInput is the request to Encrypt.
type EncryptInput struct {
	Plaintext []byte
	Format    Format
	Rules     auth.CreationRules
	Config    auth.Config
}

// EncryptResult is what Encrypt returns.
type EncryptResult struct {
	Ciphertext []byte
	Metadata   Metadata
}

// Encrypt loads plaintext, constructs master keys with injected credentials,
// generates a data key, encrypts the tree, and returns ciphertext.
func Encrypt(ctx context.Context, in EncryptInput) (*EncryptResult, error) {
	rel, err := getSem().Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: acquire semaphore: %w", err)
	}
	defer rel()

	restore := applyScopedEnv(in.Config)
	defer restore()

	store, err := StoreFor(in.Format)
	if err != nil {
		return nil, err
	}

	branches, err := store.LoadPlainFile(in.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: load plaintext: %w", err)
	}

	groups, err := BuildMasterKeysFromRules(in.Rules, in.Config)
	if err != nil {
		return nil, err
	}

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups:         groups,
			Version:           version.Version,
			LastModified:      time.Now().UTC(),
			EncryptedSuffix:   in.Rules.EncryptedSuffix,
			UnencryptedSuffix: in.Rules.UnencryptedSuffix,
			EncryptedRegex:    in.Rules.EncryptedRegex,
			UnencryptedRegex:  in.Rules.UnencryptedRegex,
			ShamirThreshold:   in.Rules.Threshold,
		},
	}

	ks := []keyservice.KeyServiceClient{keyservice.NewLocalClient()}
	dataKey, errs := tree.GenerateDataKeyWithKeyServices(ks)
	if len(errs) > 0 {
		return nil, fmt.Errorf("sopswrap: generate data key: %w", errors.Join(errs...))
	}

	if _, err := tree.Encrypt(dataKey, aes.NewCipher()); err != nil {
		return nil, fmt.Errorf("sopswrap: encrypt tree: %w", err)
	}

	out, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: emit ciphertext: %w", err)
	}

	return &EncryptResult{
		Ciphertext: out,
		Metadata:   ExtractMetadata(tree),
	}, nil
}
```

- [ ] **Step 4: Verify `sops.Metadata.ShamirThreshold` field name + `version.Version`**

Run:
```bash
go doc github.com/getsops/sops/v3.Metadata | head -30
go doc github.com/getsops/sops/v3/version
```

Expected: `Metadata` shows a `ShamirThreshold int` field and `version` package exports `Version` constant. If either differs, STOP and adapt (don't improvise — note in commit message). The field could be named `Threshold` instead; the version constant could be `MajorVersion` or in a different subpackage.

- [ ] **Step 5: Run — expect pass**

Run: `go test ./internal/sopswrap/... -v -run TestEncrypt`
Expected: 3 PASS.

- [ ] **Step 6: Confirm wider tree**

```bash
go vet ./...
go test -race ./...
```

- [ ] **Step 7: Commit**

```bash
git add internal/sopswrap/encrypt.go internal/sopswrap/encrypt_test.go
git commit -S -m "feat(sopswrap): Encrypt() orchestrator

Mirror of Decrypt() for the write path. Loads plaintext via Store,
builds fresh master keys with injected creds (BuildMasterKeysFromRules),
generates a data key, encrypts the tree, emits ciphertext.

Round-trip-tested against the age fixture key. Encrypted_regex
honored end-to-end."
```

---

### Task 4: `sopswrap.UpdateKeys` — key rotation without re-encrypting plaintext

When `rotate_keys = true` is set on a `sops_file` resource, we update the master-key list without re-encrypting the file's plaintext. Mirrors `sops updatekeys` CLI.

**Files:**
- Create: `internal/sopswrap/updatekeys.go`
- Create: `internal/sopswrap/updatekeys_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/sopswrap/updatekeys_test.go`:

```go
package sopswrap_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

func TestUpdateKeys_AddsNewRecipient(t *testing.T) {
	t.Parallel()
	pub := testAgeRecipient(t)
	// Start with a file encrypted to pub.
	enc, err := sopswrap.Encrypt(context.Background(), sopswrap.EncryptInput{
		Plaintext: []byte("k: v\n"),
		Format:    sopswrap.FormatYAML,
		Rules:     auth.CreationRules{AgeRecipients: []string{pub}},
	})
	require.NoError(t, err)
	t.Setenv("SOPS_AGE_KEY_FILE", absTestdata(t, "age-key.txt"))

	// New recipient set: original + an additional age recipient.
	newPub := "age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"
	upd, err := sopswrap.UpdateKeys(context.Background(), sopswrap.UpdateKeysInput{
		Source: enc.Ciphertext,
		Format: sopswrap.FormatYAML,
		NewRules: auth.CreationRules{
			AgeRecipients: []string{pub, newPub},
		},
	})
	require.NoError(t, err)
	require.NotEqual(t, enc.Ciphertext, upd.Ciphertext,
		"updated file must differ from original (different encrypted data key)")

	// New file decrypts successfully with the original key file.
	res, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: upd.Ciphertext,
		Format: sopswrap.FormatYAML,
	})
	require.NoError(t, err)
	require.Equal(t, "v", res.Flat["k"])
}

func TestUpdateKeys_KeepsPlaintextStable(t *testing.T) {
	t.Parallel()
	pub := testAgeRecipient(t)
	enc, err := sopswrap.Encrypt(context.Background(), sopswrap.EncryptInput{
		Plaintext: []byte("password: hunter2\n"),
		Format:    sopswrap.FormatYAML,
		Rules:     auth.CreationRules{AgeRecipients: []string{pub}},
	})
	require.NoError(t, err)
	t.Setenv("SOPS_AGE_KEY_FILE", absTestdata(t, "age-key.txt"))

	upd, err := sopswrap.UpdateKeys(context.Background(), sopswrap.UpdateKeysInput{
		Source: enc.Ciphertext,
		Format: sopswrap.FormatYAML,
		NewRules: auth.CreationRules{
			AgeRecipients: []string{pub, "age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"},
		},
	})
	require.NoError(t, err)

	// Plaintext must be unchanged.
	res, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: upd.Ciphertext,
		Format: sopswrap.FormatYAML,
	})
	require.NoError(t, err)
	require.Equal(t, "hunter2", res.Flat["password"])
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/sopswrap/... -run TestUpdateKeys`
Expected: FAIL with `undefined: sopswrap.UpdateKeys`.

- [ ] **Step 3: Implement `updatekeys.go`**

Create `internal/sopswrap/updatekeys.go`:

```go
package sopswrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	sops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/keyservice"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

// UpdateKeysInput is the request to UpdateKeys.
type UpdateKeysInput struct {
	Source   []byte
	Format   Format
	NewRules auth.CreationRules
	Config   auth.Config
}

// UpdateKeysResult is what UpdateKeys returns.
type UpdateKeysResult struct {
	Ciphertext []byte
	Metadata   Metadata
}

// UpdateKeys rotates the master-key list on an encrypted file without
// re-encrypting the file's plaintext content. Mirrors `sops updatekeys`.
func UpdateKeys(ctx context.Context, in UpdateKeysInput) (*UpdateKeysResult, error) {
	rel, err := getSem().Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer rel()

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

	// Decrypt the existing data key via the existing master keys.
	rebuilt, err := RebuildKeyGroups(tree, in.Config)
	if err != nil {
		return nil, err
	}
	tree.Metadata.KeyGroups = rebuilt

	ks := []keyservice.KeyServiceClient{keyservice.NewLocalClient()}
	dataKey, err := tree.Metadata.GetDataKeyWithKeyServices(ks, sops.DefaultDecryptionOrder)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: get data key for rotation: %w", err)
	}

	// Build the NEW master keys and re-encrypt the existing data key against them.
	newGroups, err := BuildMasterKeysFromRules(in.NewRules, in.Config)
	if err != nil {
		return nil, err
	}
	tree.Metadata.KeyGroups = newGroups
	tree.Metadata.LastModified = time.Now().UTC()

	// Encrypt-data-key step is what tree.Metadata.UpdateMasterKeys does in SOPS.
	encErrs := tree.Metadata.UpdateMasterKeysWithKeyServices(dataKey, ks)
	if len(encErrs) > 0 {
		return nil, fmt.Errorf("sopswrap: re-encrypt data key: %w", errors.Join(encErrs...))
	}

	out, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: emit rotated ciphertext: %w", err)
	}

	return &UpdateKeysResult{
		Ciphertext: out,
		Metadata:   ExtractMetadata(tree),
	}, nil
}
```

- [ ] **Step 4: Verify `tree.Metadata.UpdateMasterKeysWithKeyServices`**

Run:
```bash
go doc github.com/getsops/sops/v3.Metadata.UpdateMasterKeysWithKeyServices
```

Expected: a method that takes `dataKey []byte, svcs []keyservice.KeyServiceClient` and returns `[]error`. If the symbol doesn't exist by this name, STOP and adapt — look for `UpdateMasterKeys`, `EncryptDataKey`, or iterate manually over each MasterKey calling `EncryptIfNeeded(dataKey)`. Note any adaptation in the commit message.

- [ ] **Step 5: Run — expect pass**

Run: `go test ./internal/sopswrap/... -v -run TestUpdateKeys`
Expected: 2 PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/sopswrap/updatekeys.go internal/sopswrap/updatekeys_test.go
git commit -S -m "feat(sopswrap): UpdateKeys() rotates master keys without touching plaintext

Mirrors 'sops updatekeys' CLI. Decrypts the existing data key via the
old key set, builds new master keys from NewRules, and re-encrypts the
data key against the new set. The file's plaintext content stays
byte-identical at decrypt time — only the encrypted data-key blob
changes."
```

---

### Task 5: `resources.fileResource` — sops_file managed resource

The headline Phase 2 feature: encrypts plaintext to disk, detects drift, supports key rotation. Uses Terraform Plugin Framework's write-only attribute so plaintext never lands in state.

**Files:**
- Create: `internal/resources/file.go`
- Create: `internal/resources/drift.go`
- Create: `internal/resources/drift_test.go`
- Create: `internal/resources/file_test.go`
- Modify: `internal/provider/provider.go` (register the resource)

- [ ] **Step 1: Write the failing drift-helper test**

Create `internal/resources/drift_test.go`:

```go
package resources_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/resources"
)

func TestPlaintextDigest_StableAndDifferent(t *testing.T) {
	t.Parallel()
	a := resources.PlaintextDigest([]byte("password: hunter2\n"))
	b := resources.PlaintextDigest([]byte("password: hunter2\n"))
	c := resources.PlaintextDigest([]byte("password: hunter3\n"))
	require.Equal(t, a, b, "same plaintext must hash identically")
	require.NotEqual(t, a, c, "different plaintext must hash differently")
	require.Len(t, a, 64, "sha256 hex must be 64 chars")
}
```

- [ ] **Step 2: Run — expect fail**

Run: `go test ./internal/resources/...`
Expected: FAIL with `package resources: no Go files` or undefined.

- [ ] **Step 3: Implement `drift.go`**

Create `internal/resources/drift.go`:

```go
// Package resources implements the write-side Terraform managed resources.
package resources

import (
	"crypto/sha256"
	"encoding/hex"
)

// PlaintextDigest returns sha256(plaintext) as a 64-char hex string.
// Stored in state on Create/Update; recomputed on Read to detect drift.
func PlaintextDigest(plaintext []byte) string {
	sum := sha256.Sum256(plaintext)
	return hex.EncodeToString(sum[:])
}
```

- [ ] **Step 4: Run drift test — expect pass**

Run: `go test ./internal/resources/... -v -run TestPlaintextDigest`
Expected: PASS.

- [ ] **Step 5: Write the failing resource acceptance test**

Create `internal/resources/file_test.go`:

```go
package resources_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/elioetibr/terraform-provider-sops/internal/provider"
)

var protoV6Factory = map[string]func() (tfprotov6.ProviderServer, error){
	"sops": providerserver.NewProtocol6WithError(provider.New("test")()),
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
}

func TestAccResource_SopsFile_RoundTrip(t *testing.T) {
	root := repoRoot(t)
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(root, "testdata/age-key.txt"))

	// Read the test public key.
	keyBytes, err := os.ReadFile(filepath.Join(root, "testdata/age-key.txt"))
	if err != nil {
		t.Fatal(err)
	}
	pub := ""
	for _, line := range []byte(keyBytes) {
		_ = line
	}
	// Inline parse:
	for _, line := range splitLines(string(keyBytes)) {
		if hasPrefix(line, "# public key:") {
			pub = trimSpace(line[len("# public key:"):])
		}
	}
	if pub == "" {
		t.Fatal("could not parse public key from testdata/age-key.txt")
	}

	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "secrets.yaml")

	tf := `
resource "sops_file" "x" {
  path                = "` + target + `"
  format              = "yaml"
  content_wo          = "password: hunter2\n"
  content_wo_version  = 1
  creation_rules {
    age_recipients = ["` + pub + `"]
  }
}
data "sops_file" "verify" {
  source_file = sops_file.x.path
}
output "decrypted_password" { value = data.sops_file.verify.data["password"] }
`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{
			{
				Config: tf,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("sops_file.x", "path", target),
					resource.TestCheckOutput("decrypted_password", "hunter2"),
					resource.TestCheckResourceAttrSet("sops_file.x", "plaintext_sha256"),
				),
			},
		},
	})
}

// tiny local utils so the test file doesn't pull strings just for these
func splitLines(s string) []string {
	out := []string{}
	last := 0
	for i, r := range s {
		if r == '\n' {
			out = append(out, s[last:i])
			last = i + 1
		}
	}
	if last < len(s) {
		out = append(out, s[last:])
	}
	return out
}
func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
func trimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '\r') {
		j--
	}
	return s[i:j]
}
```

- [ ] **Step 6: Run — expect fail**

Run: `go test ./internal/resources/...`
Expected: FAIL — `resource "sops_file"` unknown.

- [ ] **Step 7: Implement `file.go`**

Create `internal/resources/file.go`:

```go
package resources

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

// ProviderDataAccessor matches the provider's exposed accessor (defined in T16
// of Phase 1). Re-declared here to avoid a circular import.
type ProviderDataAccessor interface {
	ProviderAuthConfig() auth.Config
}

type fileResource struct {
	providerCfg auth.Config
}

func NewFileResource() resource.Resource { return &fileResource{} }

func (r *fileResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_file"
}

func (r *fileResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	if acc, ok := req.ProviderData.(ProviderDataAccessor); ok {
		r.providerCfg = acc.ProviderAuthConfig()
	}
}

func (r *fileResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Encrypts plaintext to a SOPS-encrypted file on disk.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"path":   schema.StringAttribute{Required: true},
			"format": schema.StringAttribute{Required: true},
			"content_wo": schema.StringAttribute{
				Required:    true,
				WriteOnly:   true,
				Sensitive:   true,
				Description: "Plaintext to encrypt. Never stored in plan or state.",
			},
			"content_wo_version": schema.Int64Attribute{
				Required:    true,
				Description: "Bump to trigger re-encryption of content_wo.",
			},
			"rotate_keys": schema.BoolAttribute{
				Optional:    true,
				Description: "When true on Update, rotate master keys without re-encrypting plaintext.",
			},
			"plaintext_sha256": schema.StringAttribute{
				Computed:    true,
				Description: "sha256 of the decrypted plaintext at last write/read; used for drift detection.",
			},
			"mac": schema.StringAttribute{
				Computed:    true,
				Description: "SOPS MAC at last write/read.",
			},
		},
		Blocks: map[string]schema.Block{
			"creation_rules": auth.CreationRulesResourceBlockSchema(),
			"aws":            auth.AWSBlockSchemaForResource(),
			"gcp":            auth.GCPBlockSchemaForResource(),
			"azure":          auth.AzureBlockSchemaForResource(),
			"age":            auth.AgeBlockSchemaForResource(),
			"pgp":            auth.PGPBlockSchemaForResource(),
		},
	}
}

type fileModel struct {
	ID               types.String              `tfsdk:"id"`
	Path             types.String              `tfsdk:"path"`
	Format           types.String              `tfsdk:"format"`
	ContentWO        types.String              `tfsdk:"content_wo"`
	ContentWOVersion types.Int64               `tfsdk:"content_wo_version"`
	RotateKeys       types.Bool                `tfsdk:"rotate_keys"`
	PlaintextSHA256  types.String              `tfsdk:"plaintext_sha256"`
	MAC              types.String              `tfsdk:"mac"`
	CreationRules    *auth.CreationRulesModel  `tfsdk:"creation_rules"`
	AWS              *auth.AWSModel            `tfsdk:"aws"`
	GCP              *auth.GCPModel            `tfsdk:"gcp"`
	Azure            *auth.AzureModel          `tfsdk:"azure"`
	Age              *auth.AgeModel            `tfsdk:"age"`
	PGP              *auth.PGPModel            `tfsdk:"pgp"`
}

func (r *fileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan fileModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	// content_wo is write-only — read it from the Config, not Plan.
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("content_wo"), &plan.ContentWO)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cfg, rules, ok := r.buildCallCfg(ctx, &plan, &resp.Diagnostics)
	if !ok {
		return
	}

	plain := []byte(plan.ContentWO.ValueString())
	enc, err := sopswrap.Encrypt(ctx, sopswrap.EncryptInput{
		Plaintext: plain,
		Format:    sopswrap.Format(plan.Format.ValueString()),
		Rules:     rules,
		Config:    cfg,
	})
	if err != nil {
		resp.Diagnostics.AddError("sops encrypt failed", err.Error())
		return
	}

	if err := os.WriteFile(plan.Path.ValueString(), enc.Ciphertext, 0o600); err != nil {
		resp.Diagnostics.AddError("write encrypted file", err.Error())
		return
	}

	plan.ID = plan.Path
	plan.PlaintextSHA256 = types.StringValue(PlaintextDigest(plain))
	plan.MAC = types.StringValue(enc.Metadata.MAC)
	// content_wo is write-only — clear it before saving state.
	plan.ContentWO = types.StringNull()

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *fileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state fileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	src, err := os.ReadFile(state.Path.ValueString())
	if err != nil {
		if os.IsNotExist(err) {
			// File deleted out-of-band — clear from state.
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("read sops file", err.Error())
		return
	}

	cfg, _, _ := r.buildCallCfg(ctx, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	out, err := sopswrap.Decrypt(ctx, sopswrap.DecryptInput{
		Source: src,
		Format: sopswrap.Format(state.Format.ValueString()),
		Config: cfg,
	})
	if err != nil {
		resp.Diagnostics.AddError("sops decrypt failed during drift check", err.Error())
		return
	}

	// Update drift signals.
	state.PlaintextSHA256 = types.StringValue(PlaintextDigest(out.Plaintext))
	state.MAC = types.StringValue(out.Metadata.MAC)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *fileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state fileModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("content_wo"), &plan.ContentWO)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cfg, rules, ok := r.buildCallCfg(ctx, &plan, &resp.Diagnostics)
	if !ok {
		return
	}

	versionBumped := plan.ContentWOVersion.ValueInt64() != state.ContentWOVersion.ValueInt64()
	rotate := plan.RotateKeys.ValueBool()

	switch {
	case rotate:
		// Rotate keys only — don't re-encrypt plaintext.
		src, err := os.ReadFile(state.Path.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("read sops file for rotation", err.Error())
			return
		}
		upd, err := sopswrap.UpdateKeys(ctx, sopswrap.UpdateKeysInput{
			Source: src, Format: sopswrap.Format(plan.Format.ValueString()),
			NewRules: rules, Config: cfg,
		})
		if err != nil {
			resp.Diagnostics.AddError("sops updatekeys failed", err.Error())
			return
		}
		if err := os.WriteFile(plan.Path.ValueString(), upd.Ciphertext, 0o600); err != nil {
			resp.Diagnostics.AddError("write rotated sops file", err.Error())
			return
		}
		plan.PlaintextSHA256 = state.PlaintextSHA256 // unchanged by rotation
		plan.MAC = types.StringValue(upd.Metadata.MAC)

	case versionBumped:
		plain := []byte(plan.ContentWO.ValueString())
		enc, err := sopswrap.Encrypt(ctx, sopswrap.EncryptInput{
			Plaintext: plain, Format: sopswrap.Format(plan.Format.ValueString()),
			Rules: rules, Config: cfg,
		})
		if err != nil {
			resp.Diagnostics.AddError("sops re-encrypt failed", err.Error())
			return
		}
		if err := os.WriteFile(plan.Path.ValueString(), enc.Ciphertext, 0o600); err != nil {
			resp.Diagnostics.AddError("write re-encrypted file", err.Error())
			return
		}
		plan.PlaintextSHA256 = types.StringValue(PlaintextDigest(plain))
		plan.MAC = types.StringValue(enc.Metadata.MAC)

	default:
		// Nothing actionable changed — keep state values stable.
		plan.PlaintextSHA256 = state.PlaintextSHA256
		plan.MAC = state.MAC
	}

	plan.ID = plan.Path
	plan.ContentWO = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *fileResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state fileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Default: remove file. Future phase may add prevent_destroy_file.
	if err := os.Remove(state.Path.ValueString()); err != nil && !os.IsNotExist(err) {
		resp.Diagnostics.AddError("remove sops file", err.Error())
	}
}

// buildCallCfg merges per-resource auth blocks with the provider-level config
// and converts the creation_rules block to a value type. Returns false when
// diagnostics carry an error.
func (r *fileResource) buildCallCfg(ctx context.Context, m *fileModel, diags *fwDiags) (auth.Config, auth.CreationRules, bool) {
	var perCall auth.Config
	if c, d := m.AWS.ToConfig(ctx); !appendDiagsHasErr(diags, d) {
		perCall.AWS = c
	}
	if c, d := m.GCP.ToConfig(ctx); !appendDiagsHasErr(diags, d) {
		perCall.GCP = c
	}
	if c, d := m.Azure.ToConfig(ctx); !appendDiagsHasErr(diags, d) {
		perCall.Azure = c
	}
	if c, d := m.Age.ToConfig(ctx); !appendDiagsHasErr(diags, d) {
		perCall.Age = c
	}
	if c, d := m.PGP.ToConfig(ctx); !appendDiagsHasErr(diags, d) {
		perCall.PGP = c
	}
	rules, d := m.CreationRules.ToConfig(ctx)
	if appendDiagsHasErr(diags, d) {
		return auth.Config{}, auth.CreationRules{}, false
	}
	merged := auth.Merge(r.providerCfg, perCall)
	return merged, rules, !diags.HasError()
}
```

Add small adapter file `internal/resources/diags_shim.go` (so we can use `*resource.Response.Diagnostics`-style appends consistently):

```go
package resources

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// fwDiags is a thin alias used to keep buildCallCfg's signature short.
type fwDiags = diag.Diagnostics

func appendDiagsHasErr(out *fwDiags, in diag.Diagnostics) bool {
	out.Append(in...)
	return in.HasError()
}

var _ = fmt.Sprintf // keep fmt imported for future error formatting; remove if unused at commit time.
```

(If golangci-lint flags the `fmt` placeholder as unused, delete the `import "fmt"` and the `_ = fmt.Sprintf` line before committing.)

- [ ] **Step 8: Add resource-schema variants in `auth/`**

For each of `aws.go`, `gcp.go`, `azure.go`, `age.go`, `pgp.go`, add an `*BlockSchemaForResource()` function. Same attribute shapes as the existing `*BlockSchemaForDataSource()` variants, but with imports from `github.com/hashicorp/terraform-plugin-framework/resource/schema` aliased as `rschema`.

Example for `aws.go`:

```go
// At top of aws.go, add to imports:
import rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"

// Add at the end of aws.go:
func AWSBlockSchemaForResource() rschema.Block {
	return rschema.SingleNestedBlock{
		Description: "Per-resource AWS KMS credential override.",
		Attributes: map[string]rschema.Attribute{
			"profile":                  rschema.StringAttribute{Optional: true},
			"region":                   rschema.StringAttribute{Optional: true},
			"shared_config_files":      rschema.ListAttribute{Optional: true, ElementType: types.StringType},
			"shared_credentials_files": rschema.ListAttribute{Optional: true, ElementType: types.StringType},
			"env":                      rschema.MapAttribute{Optional: true, ElementType: types.StringType},
		},
		Blocks: map[string]rschema.Block{
			"assume_role": rschema.SingleNestedBlock{
				Attributes: map[string]rschema.Attribute{
					"role_arn":     rschema.StringAttribute{Optional: true},
					"session_name": rschema.StringAttribute{Optional: true},
					"external_id":  rschema.StringAttribute{Optional: true},
					"duration":     rschema.StringAttribute{Optional: true},
				},
			},
		},
	}
}
```

Mirror for GCP, Azure, age, PGP — each adds ONE function, same shape as `*BlockSchemaForDataSource` but using `resource/schema` types.

- [ ] **Step 9: Register resource in `provider.go`**

Modify `internal/provider/provider.go`:

```go
// Add import:
"github.com/elioetibr/terraform-provider-sops/internal/resources"

// Replace the Resources stub:
func (p *sopsProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		resources.NewFileResource,
	}
}
```

- [ ] **Step 10: Run — expect pass**

Run: `go test ./internal/resources/... -v`
Expected: 1 PASS (`TestPlaintextDigest_StableAndDifferent`) plus `TestAccResource_SopsFile_RoundTrip` PASSES.

If the acceptance test fails complaining about write-only attributes, verify TF version: `terraform version` — must be ≥ 1.11. Locally we have 1.9.8 which doesn't support write-only attributes — the test will need to be marked with `tfversion.SkipBelow(tfversion.Version1_11_0)` and will skip on local. Add the skip:

```go
TerraformVersionChecks: []tfversion.TerraformVersionCheck{
    tfversion.SkipBelow(tfversion.Version1_11_0),
},
```

(Add `"github.com/hashicorp/terraform-plugin-testing/tfversion"` to imports.)

- [ ] **Step 11: Confirm wider tree**

```bash
go vet ./...
go test -race ./...
```

- [ ] **Step 12: Commit**

```bash
git add internal/resources/ internal/provider/auth/*.go internal/provider/provider.go
git commit -S -m "feat(resource): sops_file managed resource with drift detection

Phase 2 headline feature. Encrypts content_wo (write-only attribute)
to disk via sopswrap.Encrypt. Read decrypts and stores sha256 +
SOPS MAC in state to detect out-of-band file edits as drift.

content_wo_version: bump to trigger re-encryption.
rotate_keys = true: rotate master keys without touching plaintext.

Adds *BlockSchemaForResource variants of the auth blocks.
Requires Terraform >= 1.11 for write-only attribute support."
```

---

### Task 6: Drift + tamper acceptance test

Goes beyond the round-trip test in Task 5: writes a file, tampers with it out-of-band, runs `terraform plan` and verifies drift is detected.

**Files:**
- Modify: `internal/resources/file_test.go`

- [ ] **Step 1: Append the failing tamper test**

Add to `internal/resources/file_test.go`:

```go
func TestAccResource_SopsFile_DriftAfterTamper(t *testing.T) {
	root := repoRoot(t)
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(root, "testdata/age-key.txt"))

	keyBytes, _ := os.ReadFile(filepath.Join(root, "testdata/age-key.txt"))
	var pub string
	for _, line := range splitLines(string(keyBytes)) {
		if hasPrefix(line, "# public key:") {
			pub = trimSpace(line[len("# public key:"):])
		}
	}

	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "secrets.yaml")

	tfStep1 := `
resource "sops_file" "x" {
  path                = "` + target + `"
  format              = "yaml"
  content_wo          = "password: hunter2\n"
  content_wo_version  = 1
  creation_rules { age_recipients = ["` + pub + `"] }
}
`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{
			{Config: tfStep1, Check: resource.TestCheckResourceAttrSet("sops_file.x", "plaintext_sha256")},
			{
				PreConfig: func() {
					// Tamper with the file: re-encrypt a DIFFERENT plaintext using sops CLI.
					if err := os.WriteFile(target+".plain", []byte("password: tampered\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					// Use the sops CLI to re-encrypt to the same recipient.
					t.Setenv("SOPS_AGE_RECIPIENTS", pub)
					if err := execSops(t, target+".plain", target); err != nil {
						t.Fatalf("tamper-encrypt: %v", err)
					}
				},
				Config:             tfStep1,
				ExpectNonEmptyPlan: true, // drift expected — plaintext_sha256 will differ
			},
		},
	})
}

func execSops(t *testing.T, in, out string) error {
	t.Helper()
	cmd := osExec("sops", "--encrypt", "--input-type", "yaml", "--output-type", "yaml", in)
	b, err := cmd.Output()
	if err != nil {
		return err
	}
	return os.WriteFile(out, b, 0o600)
}

// import "os/exec" at top and rename osExec → exec.Command
```

Add the imports needed at file top:
```go
import (
	"os/exec"
	// ... existing imports
)
```

Rename `osExec` to `exec.Command` in the function above. Removing the wrapper:

```go
func execSops(t *testing.T, in, out string) error {
	t.Helper()
	cmd := exec.Command("sops", "--encrypt", "--input-type", "yaml", "--output-type", "yaml", in)
	b, err := cmd.Output()
	if err != nil {
		return err
	}
	return os.WriteFile(out, b, 0o600)
}
```

- [ ] **Step 2: Run — should fail without drift detection**

Run: `go test ./internal/resources/... -v -run TestAccResource_SopsFile_DriftAfterTamper`
Expected: with the current Read implementation already storing `plaintext_sha256` in state, the second step's plan SHOULD see a diff on that attribute → `ExpectNonEmptyPlan: true` validates. If the test fails with "no diff produced" the drift detection is broken — debug `Read` until plan shows the change.

- [ ] **Step 3: Commit**

```bash
git add internal/resources/file_test.go
git commit -S -m "test(resource): sops_file drift detection after out-of-band tamper"
```

---

### Task 7: Key-rotation acceptance test

Verifies `rotate_keys = true` re-encrypts only the data key, not plaintext.

**Files:**
- Modify: `internal/resources/file_test.go`

- [ ] **Step 1: Append the rotation test**

Add to `internal/resources/file_test.go`:

```go
func TestAccResource_SopsFile_RotateKeys(t *testing.T) {
	root := repoRoot(t)
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(root, "testdata/age-key.txt"))

	keyBytes, _ := os.ReadFile(filepath.Join(root, "testdata/age-key.txt"))
	var pub string
	for _, line := range splitLines(string(keyBytes)) {
		if hasPrefix(line, "# public key:") {
			pub = trimSpace(line[len("# public key:"):])
		}
	}
	extraRecipient := "age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"

	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "secrets.yaml")

	tf := func(recipients string, rotate string, version int) string {
		return `
resource "sops_file" "x" {
  path                = "` + target + `"
  format              = "yaml"
  content_wo          = "password: hunter2\n"
  content_wo_version  = ` + intToStr(version) + `
  rotate_keys         = ` + rotate + `
  creation_rules { age_recipients = [` + recipients + `] }
}
data "sops_file" "verify" {
  source_file = sops_file.x.path
  depends_on  = [sops_file.x]
}
output "pwd" { value = data.sops_file.verify.data["password"] }
`
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{
			{
				Config: tf(`"`+pub+`"`, "false", 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("sops_file.x", "plaintext_sha256"),
					resource.TestCheckOutput("pwd", "hunter2"),
				),
			},
			{
				// Rotate: keep same content_wo_version (NOT bumped), add extra recipient, rotate_keys=true.
				Config: tf(`"`+pub+`", "`+extraRecipient+`"`, "true", 1),
				Check: resource.ComposeTestCheckFunc(
					// plaintext_sha256 must NOT change (plaintext is preserved through rotation).
					resource.TestCheckOutput("pwd", "hunter2"),
				),
			},
		},
	})
}

func intToStr(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}
```

- [ ] **Step 2: Run — expect pass**

Run: `go test ./internal/resources/... -v -run TestAccResource_SopsFile_RotateKeys`
Expected: PASS (gated on TF ≥ 1.11; skips locally on 1.9.8).

- [ ] **Step 3: Commit**

```bash
git add internal/resources/file_test.go
git commit -S -m "test(resource): sops_file rotate_keys preserves plaintext

Verifies that toggling rotate_keys = true and adding a new age recipient
updates the encrypted file but leaves plaintext (decrypted by data
source) byte-identical."
```

---

### Task 8: Example Terraform config for the resource

**Files:**
- Create: `examples/encrypt-resource/main.tf`

- [ ] **Step 1: Write the example**

Create `examples/encrypt-resource/main.tf`:

```hcl
terraform {
  required_version = ">= 1.11"
  required_providers {
    sops = {
      source  = "elioetibr/sops"
      version = ">= 0.2.0"
    }
  }
}

provider "sops" {
  age { key_file = pathexpand("~/.config/sops/age/keys.txt") }
}

resource "sops_file" "secrets" {
  path                = "${path.module}/secrets.yaml"
  format              = "yaml"
  content_wo          = jsonencode({
    database = {
      host     = "db.example.com"
      password = var.db_password
    }
  })
  content_wo_version = 1

  creation_rules {
    age_recipients = ["age1..."]
  }
}

variable "db_password" {
  type      = string
  sensitive = true
}
```

- [ ] **Step 2: Verify it parses with terraform fmt**

Run:
```bash
cd examples/encrypt-resource && terraform fmt -check && cd ../..
```
Expected: no errors. (Don't run `terraform init` — the provider isn't installed for v0.2 yet.)

- [ ] **Step 3: Commit**

```bash
git add examples/encrypt-resource/
git commit -S -m "docs(examples): encrypt-resource example for sops_file resource"
```

---

### Task 9: README + status update

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update Status section**

Find the "Status" section in `README.md` and update Phase 2 from "Planned" to "Shipped". Also add a short subsection above with the new resource:

Add this `## Encrypting files` section right after the "Quick start" section:

```markdown
## Encrypting files

Use the `sops_file` resource (write-only attribute keeps plaintext out of state):

```hcl
resource "sops_file" "secrets" {
  path                = "secrets.yaml"
  format              = "yaml"
  content_wo          = var.plaintext
  content_wo_version  = 1
  creation_rules {
    age_recipients = ["age1..."]
  }
}
```

- `content_wo` is a Terraform write-only attribute (TF ≥ 1.11). It is never serialized to plan or state.
- Bump `content_wo_version` to trigger re-encryption.
- Set `rotate_keys = true` to rotate master keys without touching plaintext.
- Read detects drift via `sha256(plaintext)` + SOPS MAC stored in state.
```

Update Status block:

```
**Phase 1 (v0.1.x):** decrypt + per-call credential injection. Shipped.
**Phase 2 (v0.2.x):** sops_file write resource + drift detection. Shipped.
**Phase 3 (v0.3.x):** provider functions + LRU cache + Vault. Planned.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -S -m "docs: README — add sops_file resource section, mark Phase 2 shipped"
```

---

### Task 10: Final verification

- [ ] **Step 1: Full suite**

Run:
```bash
go vet ./...
go test -race -count=1 ./...
go build ./...
```
Expected: all clean.

- [ ] **Step 2: Lint**

Run: `golangci-lint run`
Expected: clean (or only stylistic hints).

- [ ] **Step 3: Example fmt check**

Run:
```bash
for d in examples/*/; do
  (cd "$d" && terraform fmt -check) || echo "FAIL: $d"
done
```
Expected: no failures.

- [ ] **Step 4: Smoke test**

Run:
```bash
make install VERSION=0.2.0-rc1
cat > /tmp/dev.tfrc <<EOF
provider_installation {
  filesystem_mirror {
    path    = "$HOME/.terraform.d/plugins"
    include = ["registry.terraform.io/elioetibr/sops"]
  }
  direct {
    exclude = ["registry.terraform.io/elioetibr/sops"]
  }
}
EOF
cd examples/encrypt-resource
TF_CLI_CONFIG_FILE=/tmp/dev.tfrc terraform init
TF_CLI_CONFIG_FILE=/tmp/dev.tfrc terraform validate
cd ../..
rm /tmp/dev.tfrc examples/encrypt-resource/.terraform.lock.hcl
rm -rf examples/encrypt-resource/.terraform
```
Expected: `Success! The configuration is valid.`

- [ ] **Step 5: Report**

Open Phase 2 PR or tag `v0.2.0-rc1` per the maintainer's release process. **Do NOT push or tag without explicit user okay.**

---

## Self-Review

**Spec coverage check (vs spec §6.4 / §11 / §14):**

| Spec item | Plan task |
|---|---|
| `resource "sops_file"` with `path`, `format`, `content_wo`, `content_wo_version` | Task 5 |
| `creation_rules` with kms/gcp/azure/age/pgp + encrypted_regex etc. | Tasks 1, 5 |
| `rotate_keys = true` for key rotation | Tasks 4, 5, 7 |
| Drift detection via MAC | Task 5 (Read) + Task 6 acceptance |
| `content_wo` write-only — never in plan/state | Task 5 (schema marks `WriteOnly: true`; Create/Update set `plan.ContentWO = StringNull()` before State.Set) |
| Round-trip encrypt → decrypt acceptance test | Task 5 (TestAccResource_SopsFile_RoundTrip) |
| Tamper-detection acceptance test | Task 6 |
| Rotation acceptance test | Task 7 |
| Per-resource auth override blocks | Task 5 schema includes aws/gcp/azure/age/pgp; Task 5 step 8 adds the `*BlockSchemaForResource` variants in auth/*.go |
| Examples for encrypt-resource | Task 8 |
| README update | Task 9 |
| Concurrency-safe (reuses Phase 1 semaphore) | Task 3 (Encrypt) uses `getSem().Acquire`; Task 4 (UpdateKeys) likewise |

**Placeholder scan:**
- No "TBD" / "implement later" / "add appropriate validation" without specifics. Two notes about "verify the API symbol exists" (Task 2 step 4, Task 3 step 4, Task 4 step 4) are explicit instructions to STOP and report — that's deliberate, not a placeholder.
- The `diags_shim.go` has a deliberate `_ = fmt.Sprintf` placeholder import which the plan calls out for deletion at commit time.

**Type consistency check:**
- `auth.CreationRules` (T1) used by `BuildMasterKeysFromRules` (T2), `Encrypt` (T3), `UpdateKeys` (T4), `fileResource` (T5).
- `sopswrap.EncryptInput` / `EncryptResult` (T3) consumed by `fileResource.Create` and `fileResource.Update` (T5).
- `sopswrap.UpdateKeysInput` / `UpdateKeysResult` (T4) consumed by `fileResource.Update` (T5).
- `ProviderDataAccessor` interface (T5) matches what `provider.ProviderData.ProviderAuthConfig()` already returns (Phase 1).
- `PlaintextDigest` (T5 drift.go) consumed by `fileResource.Create/Read/Update`.
- All field names match across task definitions and consumers.

**Scope check:** Phase 2 only. No Phase 3 spill (no provider functions, no LRU cache, no Vault). Right-sized for one execution session.

---

**Next step after this plan is approved:** Invoke `superpowers:subagent-driven-development` (same execution mode as Phase 1) to dispatch implementers task-by-task.
