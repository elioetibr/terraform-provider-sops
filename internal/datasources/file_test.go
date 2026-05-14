package datasources_test

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
output "pwd" {
  value     = data.sops_file.x.data["database.password"]
  sensitive = true
}
output "api_key" {
  value     = data.sops_file.x.data["api_key"]
  sensitive = true
}
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
output "structured" {
  value     = jsondecode(data.sops_file.x.data_json).database.password
  sensitive = true
}
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
output "pwd" {
  value     = data.sops_file.x.data["database.password"]
  sensitive = true
}
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
