//go:build acceptance

package sopswrap_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

// TestAccAWSKMS_ProfileInjection verifies that setting AWSConfig.Profile is
// sufficient to decrypt a real KMS-encrypted SOPS file — WITHOUT exporting
// AWS_PROFILE to the test process. This is the headline fix.
func TestAccAWSKMS_ProfileInjection(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("TF_ACC=1 required for acceptance tests")
	}
	profile := os.Getenv("SOPS_TEST_AWS_PROFILE")
	if profile == "" {
		t.Skip("SOPS_TEST_AWS_PROFILE not set")
	}
	arn := os.Getenv("SOPS_TEST_KMS_ARN")
	if arn == "" {
		t.Skip("SOPS_TEST_KMS_ARN not set")
	}

	// Make sure AWS_PROFILE is NOT in the test env — proves we don't depend on it.
	os.Unsetenv("AWS_PROFILE")

	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.yaml")
	enc := filepath.Join(dir, "enc.yaml")
	require.NoError(t, os.WriteFile(plain, []byte("password: hunter2\n"), 0o600))

	// Encrypt using sops CLI with AWS_PROFILE in the encrypt step (allowed —
	// the test only proves AWS_PROFILE is not required for DECRYPT).
	cmd := exec.Command("sops", "--encrypt", "--kms", arn, "--input-type", "yaml", "--output-type", "yaml", plain)
	cmd.Env = append(os.Environ(), "AWS_PROFILE="+profile)
	out, err := cmd.Output()
	require.NoError(t, err, "encryption setup failed: %s", out)
	require.NoError(t, os.WriteFile(enc, out, 0o600))

	src, err := os.ReadFile(enc)
	require.NoError(t, err)

	result, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: src,
		Format: sopswrap.FormatYAML,
		Config: auth.Config{
			AWS: auth.AWSConfig{Profile: profile},
		},
	})
	require.NoError(t, err)
	require.Contains(t, string(result.Plaintext), "hunter2")
}
