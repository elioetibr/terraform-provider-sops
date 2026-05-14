package resources_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/elioetibr/terraform-provider-sops/internal/provider"
)

var protoV6Factory = map[string]func() (tfprotov6.ProviderServer, error){
	"sops": providerserver.NewProtocol6WithError(provider.New("test")()),
}

// repoRoot returns the repository root by walking up from this test file.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// thisFile = .../internal/resources/file_test.go
	// Repo root is two directories up.
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
}

// agePublicKey reads the age public key from testdata/age-key.txt.
// The file format is:
//
//	# created: ...
//	# public key: <pubkey>
//	AGE-SECRET-KEY-...
func agePublicKey(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "testdata/age-key.txt"))
	if err != nil {
		t.Fatalf("could not read age-key.txt: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "# public key:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "# public key:"))
		}
	}
	t.Fatal("age-key.txt: could not find '# public key:' line")
	return ""
}

// fileExistsCheck returns a TestCheckFunc that verifies a file exists on disk.
func fileExistsCheck(path string) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("expected encrypted file at %q: %w", path, err)
		}
		return nil
	}
}

// TestAccResource_SopsFile_RoundTrip verifies the full create → read → update lifecycle:
//  1. Create encrypts content_wo to disk and stores plaintext_sha256 in state.
//  2. Plan shows no diff after create.
//  3. Update (version bump) re-encrypts with new content and updates the sha256.
//
// Requires Terraform >= 1.11 for write-only attribute support.
// The test is automatically skipped on older Terraform versions.
func TestAccResource_SopsFile_RoundTrip(t *testing.T) {
	root := repoRoot(t)
	keyFile := filepath.Join(root, "testdata/age-key.txt")
	pubKey := agePublicKey(t)

	t.Setenv("SOPS_AGE_KEY_FILE", keyFile)

	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "secrets.yaml")

	// HCL for the initial create step.
	configV1 := `
resource "sops_file" "test" {
  path               = "` + destPath + `"
  content_wo         = "database:\n  password: hunter2\n"
  content_wo_version = "v1"
  input_type         = "yaml"

  creation_rules {
    age_recipients = ["` + pubKey + `"]
  }
}
`
	// HCL for the update step (version bumped, new content).
	configV2 := `
resource "sops_file" "test" {
  path               = "` + destPath + `"
  content_wo         = "database:\n  password: changed\n"
  content_wo_version = "v2"
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
			{
				// Step 1: Create.
				Config: configV1,
				Check: resource.ComposeTestCheckFunc(
					// id is the path.
					resource.TestCheckResourceAttr("sops_file.test", "id", destPath),
					// content_wo_version is stored.
					resource.TestCheckResourceAttr("sops_file.test", "content_wo_version", "v1"),
					// input_type is set.
					resource.TestCheckResourceAttr("sops_file.test", "input_type", "yaml"),
					// plaintext_sha256 is computed and non-empty.
					resource.TestCheckResourceAttrSet("sops_file.test", "plaintext_sha256"),
					// sops_mac is computed and non-empty.
					resource.TestCheckResourceAttrSet("sops_file.test", "sops_mac"),
					// Encrypted file exists on disk.
					fileExistsCheck(destPath),
				),
			},
			{
				// Step 2: Plan after Create should show no diff.
				Config:             configV1,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				// Step 3: Update — version bumped triggers re-encryption.
				Config: configV2,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("sops_file.test", "content_wo_version", "v2"),
					resource.TestCheckResourceAttrSet("sops_file.test", "plaintext_sha256"),
				),
			},
		},
	})
}
