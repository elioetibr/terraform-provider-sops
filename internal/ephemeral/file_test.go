package ephemeral_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/elioetibr/terraform-provider-sops/internal/provider"
)

var protoV6Factory = map[string]func() (tfprotov6.ProviderServer, error){
	"sops": providerserver.NewProtocol6WithError(provider.New("test")()),
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// .../internal/ephemeral/file_test.go -> repo root (3 dirs up)
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
}

func TestAccEphemeral_SopsFile_YAML(t *testing.T) {
	root := repoRoot(t)
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(root, "testdata/age-key.txt"))

	fixture := filepath.Join(root, "testdata/secrets.yaml")
	// Ephemeral outputs are not allowed at the root module in TF 1.11+;
	// we consume the ephemeral value via a check block instead, which is
	// the canonical pattern for asserting on ephemeral data in tests.
	tf := `
ephemeral "sops_file" "x" {
  source_file = "` + fixture + `"
  input_type  = "yaml"
}
check "decrypted_password" {
  assert {
    condition     = ephemeral.sops_file.x.data["database.password"] != ""
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
