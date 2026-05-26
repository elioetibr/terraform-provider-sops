package ephemeral_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

func TestAccEphemeral_SopsExternal_YAML(t *testing.T) {
	root := repoRoot(t)
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(root, "testdata/age-key.txt"))

	fixture := filepath.Join(root, "testdata/secrets.yaml")
	src, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("could not read fixture: %v", err)
	}
	escaped := escapeHCLString(string(src))

	// Ephemeral outputs are not allowed at the root module in TF 1.11+;
	// we consume the ephemeral value via a check block instead.
	tf := `
ephemeral "sops_external" "x" {
  source     = "` + escaped + `"
  input_type = "yaml"
}
check "decrypted_password" {
  assert {
    condition     = ephemeral.sops_external.x.data["database.password"] != ""
    error_message = "expected decrypted database.password to be non-empty"
  }
}
`

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{
			{
				Config: tf,
			},
		},
	})
}

// escapeHCLString replaces backslash, double-quote, and newlines so the
// fixture YAML can be embedded as an HCL string literal.
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
