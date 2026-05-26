package datasources_test

import (
	"path/filepath"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccDataSource_SopsFile_AutoDetectsFormat covers the
// `format == ""` branch in datasources/file.go Read.
func TestAccDataSource_SopsFile_AutoDetectsFormat(t *testing.T) {
	root := repoRoot(t)
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(root, "testdata/age-key.txt"))

	fixture := filepath.Join(root, "testdata/secrets.yaml")
	tf := `
data "sops_file" "x" {
  source_file = "` + fixture + `"
  # input_type intentionally omitted — exercise FormatFromPath()
}
output "pwd" {
  value     = data.sops_file.x.data["database.password"]
  sensitive = true
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{{
			Config: tf,
			Check:  resource.TestCheckOutput("pwd", "hunter2"),
		}},
	})
}

// TestAccDataSource_SopsFile_NotFound covers the ReadFile-error branch.
func TestAccDataSource_SopsFile_NotFound(t *testing.T) {
	tf := `
data "sops_file" "x" {
  source_file = "/this/path/definitely/does/not/exist.yaml"
  input_type  = "yaml"
}
output "pwd" {
  value     = data.sops_file.x.data["k"]
  sensitive = true
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{{
			Config:      tf,
			ExpectError: regexp.MustCompile("could not read source_file"),
		}},
	})
}

// TestAccDataSource_SopsFile_DecryptFailure covers the Decrypt-error branch
// by feeding a plain (non-SOPS) text file.
func TestAccDataSource_SopsFile_DecryptFailure(t *testing.T) {
	root := repoRoot(t)
	// Point at the age key file itself, which is plain text and not a SOPS envelope.
	fixture := filepath.Join(root, "testdata/age-key.txt")

	tf := `
data "sops_file" "x" {
  source_file = "` + fixture + `"
  input_type  = "yaml"
}
output "pwd" {
  value     = data.sops_file.x.data["k"]
  sensitive = true
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{{
			Config:      tf,
			ExpectError: regexp.MustCompile("sops decrypt failed|sopswrap"),
		}},
	})
}

// TestAccDataSource_SopsExternal_DecryptFailure covers the
// Decrypt-error branch for the external datasource.
func TestAccDataSource_SopsExternal_DecryptFailure(t *testing.T) {
	tf := `
data "sops_external" "x" {
  source     = "this is not sops content"
  input_type = "yaml"
}
output "pwd" {
  value     = data.sops_external.x.data["k"]
  sensitive = true
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{{
			Config:      tf,
			ExpectError: regexp.MustCompile("sops decrypt failed|sopswrap"),
		}},
	})
}
