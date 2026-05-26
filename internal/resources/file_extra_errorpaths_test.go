package resources_test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

// TestAccResource_SopsFile_ReadPermissionDenied covers Read's non-IsNotExist
// error branch (and ModifyPlan's ReadFile failure path) by chmodding the
// encrypted file to 0o000 between apply and the next plan.
func TestAccResource_SopsFile_ReadPermissionDenied(t *testing.T) {
	root := repoRoot(t)
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(root, "testdata/age-key.txt"))
	pubKey := agePublicKey(t)
	tmpDir := t.TempDir()
	dest := filepath.Join(tmpDir, "secrets.yaml")

	tf := `
resource "sops_file" "pd" {
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
		Steps: []resource.TestStep{
			{Config: tf, Check: fileExistsCheck(dest)},
			{
				PreConfig: func() {
					// Make the file fully unreadable: ReadFile inside Read and
					// ModifyPlan both return permission errors.
					if err := os.Chmod(dest, 0o000); err != nil {
						t.Fatalf("chmod: %v", err)
					}
					t.Cleanup(func() { _ = os.Chmod(dest, 0o600) })
				},
				Config:      tf,
				ExpectError: regexp.MustCompile(`could not read encrypted file|permission denied`),
			},
		},
	})
}

// TestAccResource_SopsFile_CreateBadAWSDuration drives buildPerCallConfig to
// surface a diagnostic in Create — covers Create's perCall HasError branch.
func TestAccResource_SopsFile_CreateBadAWSDuration(t *testing.T) {
	root := repoRoot(t)
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(root, "testdata/age-key.txt"))
	pubKey := agePublicKey(t)
	tmpDir := t.TempDir()
	dest := filepath.Join(tmpDir, "secrets.yaml")

	tf := `
resource "sops_file" "bad" {
  path               = "` + dest + `"
  content_wo         = "password: hunter2\n"
  content_wo_version = "1"
  input_type         = "yaml"

  aws {
    assume_role {
      role_arn = "arn:aws:iam::1:role/r"
      duration = "not-a-duration"
    }
  }

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
			ExpectError: regexp.MustCompile(`invalid duration|could not parse`),
		}},
	})
}

// TestAccResource_SopsFile_CreateEmptyCreationRules exercises the ToConfig
// failure branch in Create: a creation_rules block with no key source.
func TestAccResource_SopsFile_CreateEmptyCreationRules(t *testing.T) {
	tmpDir := t.TempDir()
	dest := filepath.Join(tmpDir, "secrets.yaml")

	tf := `
resource "sops_file" "empty_rules" {
  path               = "` + dest + `"
  content_wo         = "password: hunter2\n"
  content_wo_version = "1"
  input_type         = "yaml"

  creation_rules {}
}
`
	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_11_0),
		},
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{{
			Config:      tf,
			ExpectError: regexp.MustCompile(`creation_rules requires at least one key source`),
		}},
	})
}

// TestAccResource_SopsFile_RotateKeysEmptyCreationRules covers doKeyRotation's
// ToConfig failure branch.
func TestAccResource_SopsFile_RotateKeysEmptyCreationRules(t *testing.T) {
	root := repoRoot(t)
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(root, "testdata/age-key.txt"))
	pubKey := agePublicKey(t)
	tmpDir := t.TempDir()
	dest := filepath.Join(tmpDir, "secrets.yaml")

	v1 := `
resource "sops_file" "rk" {
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
resource "sops_file" "rk" {
  path               = "` + dest + `"
  content_wo         = "password: hunter2\n"
  content_wo_version = "1"
  input_type         = "yaml"
  rotate_keys        = true

  creation_rules {}
}
`
	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_11_0),
		},
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{
			{Config: v1, Check: fileExistsCheck(dest)},
			{Config: v2, ExpectError: regexp.MustCompile(`creation_rules requires at least one key source`)},
		},
	})
}

// TestAccResource_SopsFile_ReEncryptEmptyCreationRules covers doReEncrypt's
// ToConfig failure branch.
func TestAccResource_SopsFile_ReEncryptEmptyCreationRules(t *testing.T) {
	root := repoRoot(t)
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(root, "testdata/age-key.txt"))
	pubKey := agePublicKey(t)
	tmpDir := t.TempDir()
	dest := filepath.Join(tmpDir, "secrets.yaml")

	v1 := `
resource "sops_file" "re" {
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
resource "sops_file" "re" {
  path               = "` + dest + `"
  content_wo         = "password: changed\n"
  content_wo_version = "2"
  input_type         = "yaml"

  creation_rules {}
}
`
	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_11_0),
		},
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{
			{Config: v1, Check: fileExistsCheck(dest)},
			{Config: v2, ExpectError: regexp.MustCompile(`creation_rules requires at least one key source`)},
		},
	})
}

// TestAccResource_SopsFile_UpdateBadAWSDuration: bumping content_wo_version
// with an invalid aws.assume_role.duration exercises Update's perCall HasError
// branch (before doReEncrypt is reached).
func TestAccResource_SopsFile_UpdateBadAWSDuration(t *testing.T) {
	root := repoRoot(t)
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(root, "testdata/age-key.txt"))
	pubKey := agePublicKey(t)
	tmpDir := t.TempDir()
	dest := filepath.Join(tmpDir, "secrets.yaml")

	v1 := `
resource "sops_file" "u" {
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
resource "sops_file" "u" {
  path               = "` + dest + `"
  content_wo         = "password: changed\n"
  content_wo_version = "2"
  input_type         = "yaml"

  aws {
    assume_role {
      role_arn = "arn:aws:iam::1:role/r"
      duration = "not-a-duration"
    }
  }

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
		Steps: []resource.TestStep{
			{Config: v1, Check: fileExistsCheck(dest)},
			{Config: v2, ExpectError: regexp.MustCompile(`invalid duration|could not parse`)},
		},
	})
}
