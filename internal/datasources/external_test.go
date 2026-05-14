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

	// Read the encrypted fixture file as a string to pass via source attr.
	fixture := filepath.Join(root, "testdata/secrets.yaml")
	src, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("could not read fixture: %v", err)
	}
	escaped := escapeHCLString(string(src))

	tf := `
data "sops_external" "x" {
  source     = "` + escaped + `"
  input_type = "yaml"
}
output "pwd" {
  value     = data.sops_external.x.data["database.password"]
  sensitive = true
}
output "api_key" {
  value     = data.sops_external.x.data["api_key"]
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
}

// escapeHCLString replaces backslash and double-quote so the fixture YAML can
// be embedded as an HCL string literal.
func escapeHCLString(s string) string {
	out := make([]byte, 0, len(s)+32)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			out = append(out, '\\', '\\')
		case '"':
			out = append(out, '\\', '"')
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		default:
			out = append(out, s[i])
		}
	}
	return string(out)
}
