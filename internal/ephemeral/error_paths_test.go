package ephemeral_test

import (
	"path/filepath"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

// TestAccEphemeral_SopsFile_AutoDetectsFormat covers the FormatFromPath path
// in ephemeral/file.go Open.
func TestAccEphemeral_SopsFile_AutoDetectsFormat(t *testing.T) {
	root := repoRoot(t)
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(root, "testdata/age-key.txt"))

	fixture := filepath.Join(root, "testdata/secrets.yaml")
	tf := `
ephemeral "sops_file" "x" {
  source_file = "` + fixture + `"
  # input_type omitted — exercise FormatFromPath()
}
check "decrypted" {
  assert {
    condition     = ephemeral.sops_file.x.data["database.password"] != ""
    error_message = "expected non-empty decrypted password"
  }
}
`
	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: protoV6Factory,
		Steps:                    []resource.TestStep{{Config: tf}},
	})
}

// TestAccEphemeral_SopsFile_NotFound covers the ReadFile-error branch.
func TestAccEphemeral_SopsFile_NotFound(t *testing.T) {
	tf := `
ephemeral "sops_file" "x" {
  source_file = "/this/path/definitely/does/not/exist.yaml"
  input_type  = "yaml"
}
check "x" {
  assert {
    condition     = ephemeral.sops_file.x.data["k"] != ""
    error_message = "unused"
  }
}
`
	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{{
			Config:      tf,
			ExpectError: regexp.MustCompile("could not read source_file"),
		}},
	})
}

// TestAccEphemeral_SopsFile_DecryptFailure covers the Decrypt-error branch
// by feeding a plain (non-SOPS) text file.
func TestAccEphemeral_SopsFile_DecryptFailure(t *testing.T) {
	root := repoRoot(t)
	fixture := filepath.Join(root, "testdata/age-key.txt")

	tf := `
ephemeral "sops_file" "x" {
  source_file = "` + fixture + `"
  input_type  = "yaml"
}
check "x" {
  assert {
    condition     = ephemeral.sops_file.x.data["k"] != ""
    error_message = "unused"
  }
}
`
	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{{
			Config:      tf,
			ExpectError: regexp.MustCompile("sops decrypt failed|sopswrap"),
		}},
	})
}

// TestAccEphemeral_SopsExternal_DecryptFailure covers the
// Decrypt-error branch for the external ephemeral.
func TestAccEphemeral_SopsExternal_DecryptFailure(t *testing.T) {
	tf := `
ephemeral "sops_external" "x" {
  source     = "this is not sops content"
  input_type = "yaml"
}
check "x" {
  assert {
    condition     = ephemeral.sops_external.x.data["k"] != ""
    error_message = "unused"
  }
}
`
	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{{
			Config:      tf,
			ExpectError: regexp.MustCompile("sops decrypt failed|sopswrap"),
		}},
	})
}
