package resources_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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

// TestAccResource_SopsFile_DriftAfterTamper verifies that when the encrypted
// file is overwritten out-of-band with a different plaintext, Terraform detects
// drift via the changed plaintext_sha256 and produces a non-empty plan.
//
// Requires Terraform >= 1.11 for write-only attribute support.
// The test is automatically skipped on older Terraform versions.
func TestAccResource_SopsFile_DriftAfterTamper(t *testing.T) {
	root := repoRoot(t)
	keyFile := filepath.Join(root, "testdata/age-key.txt")
	pubKey := agePublicKey(t)

	t.Setenv("SOPS_AGE_KEY_FILE", keyFile)

	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "secrets.yaml")

	tfConfig := `
resource "sops_file" "x" {
  path               = "` + target + `"
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
			{
				Config: tfConfig,
				Check:  resource.TestCheckResourceAttrSet("sops_file.x", "plaintext_sha256"),
			},
			{
				PreConfig: func() {
					// Write a different plaintext and re-encrypt using the sops CLI.
					plainFile := target + ".plain"
					if err := os.WriteFile(plainFile, []byte("password: tampered\n"), 0o600); err != nil {
						t.Fatalf("tamper write: %v", err)
					}
					// Tell the sops CLI which age recipient to encrypt to.
					t.Setenv("SOPS_AGE_RECIPIENTS", pubKey)
					if err := execSops(t, plainFile, target); err != nil {
						t.Fatalf("tamper re-encrypt: %v", err)
					}
				},
				Config:             tfConfig,
				ExpectNonEmptyPlan: true, // drift detected via differing plaintext_sha256
			},
		},
	})
}

// execSops encrypts the file at in using the sops CLI and writes the result to out.
// SOPS_AGE_KEY_FILE and SOPS_AGE_RECIPIENTS must already be set in the environment.
func execSops(t *testing.T, in, out string) error {
	t.Helper()
	cmd := exec.Command("sops", "--encrypt", "--input-type", "yaml", "--output-type", "yaml", in)
	b, err := cmd.Output()
	if err != nil {
		return err
	}
	return os.WriteFile(out, b, 0o600)
}

// TestAccResource_SopsFile_RotateKeys verifies that setting rotate_keys = true
// updates the encrypted master-key list without altering the plaintext content.
// A data source reads back the decrypted value to confirm byte-identity.
//
// Requires Terraform >= 1.11 for write-only attribute support.
// The test is automatically skipped on older Terraform versions.
func TestAccResource_SopsFile_RotateKeys(t *testing.T) {
	root := repoRoot(t)
	keyFile := filepath.Join(root, "testdata/age-key.txt")
	pubKey := agePublicKey(t)

	t.Setenv("SOPS_AGE_KEY_FILE", keyFile)

	// A second age recipient added during key rotation.
	// This is a well-known test key — safe to hardcode in tests.
	extraRecipient := "age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"

	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "secrets.yaml")

	// tf generates the HCL for a given recipient list, rotate flag, and version token.
	tf := func(recipients string, rotate string, version int) string {
		return `
resource "sops_file" "x" {
  path               = "` + target + `"
  content_wo         = "password: hunter2\n"
  content_wo_version = "` + strconv.Itoa(version) + `"
  input_type         = "yaml"
  rotate_keys        = ` + rotate + `

  creation_rules {
    age_recipients = [` + recipients + `]
  }
}

data "sops_file" "verify" {
  source_file = sops_file.x.path
  depends_on  = [sops_file.x]
}

output "pwd" {
  value     = data.sops_file.verify.data["password"]
  sensitive = true
}
`
	}

	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_11_0),
		},
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{
			{
				// Step 1: Create with a single age recipient, rotate_keys off.
				Config: tf(`"`+pubKey+`"`, "false", 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("sops_file.x", "plaintext_sha256"),
					resource.TestCheckOutput("pwd", "hunter2"),
				),
			},
			{
				// Step 2: Add an extra recipient and rotate_keys = true.
				// content_wo_version is intentionally NOT bumped — only key rotation occurs.
				// The decrypted plaintext must still equal "hunter2".
				Config: tf(`"`+pubKey+`", "`+extraRecipient+`"`, "true", 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckOutput("pwd", "hunter2"),
				),
			},
		},
	})
}
