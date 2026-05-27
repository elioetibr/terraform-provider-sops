package resources_test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

// TestAccResource_SopsFile_CreateWriteFails covers the WriteFile-error branch
// in Create (file.go:201-204). The destination's parent directory exists but
// is 0o555 (read+exec, no write). MkdirAll is a no-op on an existing directory
// per Go's docs, so the flow reaches os.WriteFile, which then fails with
// EACCES — closing the partial (201) + miss (202-204) pair on codecov.
func TestAccResource_SopsFile_CreateWriteFails(t *testing.T) {
	root := repoRoot(t)
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(root, "testdata/age-key.txt"))
	pubKey := agePublicKey(t)

	tmpDir := t.TempDir()
	ro := filepath.Join(tmpDir, "readonly")
	if err := os.MkdirAll(ro, 0o555); err != nil {
		t.Fatalf("mkdir readonly: %v", err)
	}
	// Restore writeable mode at end so t.TempDir cleanup can rm-rf.
	t.Cleanup(func() { _ = os.Chmod(ro, 0o755) })

	dest := filepath.Join(ro, "secrets.yaml")
	tf := `
resource "sops_file" "ro" {
  path               = "` + dest + `"
  content_wo         = "password: hunter2\n"
  content_wo_version = "1"
  input_type         = "yaml"

  creation_rules {
    age_recipients = ["` + pubKey + `"]
  }
}
`
	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_11_0),
		},
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{{
			Config:      tf,
			ExpectError: regexp.MustCompile(`could not write encrypted file|permission denied`),
		}},
	})
}

// TestAccResource_SopsFile_RotateKeysUpdateMasterKeysFails covers the
// UpdateMasterKeysWithKeyServices-error branch inside doKeyRotation
// (file.go:356-359). After a successful Create, a rotate-keys Apply lists a
// PGP fingerprint that has no matching key on the local gpg keyring. The
// existing-tree decrypt succeeds (age recipient still valid), but the
// re-encrypt-data-key step fails when gpg cannot encrypt to the unknown
// PGP fingerprint — the failure surfaces via sopswrap.UpdateKeys.
func TestAccResource_SopsFile_RotateKeysUpdateMasterKeysFails(t *testing.T) {
	root := repoRoot(t)
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(root, "testdata/age-key.txt"))
	pubKey := agePublicKey(t)
	tmpDir := t.TempDir()
	dest := filepath.Join(tmpDir, "secrets.yaml")

	v1 := `
resource "sops_file" "rot" {
  path               = "` + dest + `"
  content_wo         = "password: hunter2\n"
  content_wo_version = "1"
  input_type         = "yaml"

  creation_rules {
    age_recipients = ["` + pubKey + `"]
  }
}
`
	v2 := `
resource "sops_file" "rot" {
  path               = "` + dest + `"
  content_wo         = "password: hunter2\n"
  content_wo_version = "1"
  input_type         = "yaml"
  rotate_keys        = true

  creation_rules {
    age_recipients   = ["` + pubKey + `"]
    pgp_fingerprints = ["DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"]
  }
}
`
	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_11_0),
		},
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{
			{Config: v1, Check: fileExistsCheck(dest)},
			{
				Config:      v2,
				ExpectError: regexp.MustCompile(`sops key rotation failed|re-encrypt data key`),
			},
		},
	})
}
