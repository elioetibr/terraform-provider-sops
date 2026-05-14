package sopswrap_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

func testAgeRecipient(t *testing.T) string {
	t.Helper()
	// Read the public key out of testdata/age-key.txt (the second '#' header line).
	b, err := os.ReadFile(absTestdata(t, "age-key.txt"))
	require.NoError(t, err)
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "# public key:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "# public key:"))
		}
	}
	t.Fatal("could not find public key in testdata/age-key.txt")
	return ""
}

func TestEncrypt_YAMLRoundTrip(t *testing.T) {
	// NOTE: no t.Parallel() — this test calls t.Setenv, which is incompatible
	// with t.Parallel() in Go 1.21+.
	pub := testAgeRecipient(t)

	plain := []byte("password: hunter2\napi_key: sk-test-12345\n")

	enc, err := sopswrap.Encrypt(context.Background(), sopswrap.EncryptInput{
		Plaintext: plain,
		Format:    sopswrap.FormatYAML,
		Rules:     auth.CreationRules{AgeRecipients: []string{pub}},
		Config:    auth.Config{},
	})
	require.NoError(t, err)
	require.NotEmpty(t, enc.Ciphertext)
	require.Contains(t, string(enc.Ciphertext), "sops:",
		"encrypted file must carry sops metadata")

	// Round-trip via Decrypt — should recover the original.
	t.Setenv("SOPS_AGE_KEY_FILE", absTestdata(t, "age-key.txt"))
	res, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: enc.Ciphertext,
		Format: sopswrap.FormatYAML,
	})
	require.NoError(t, err)
	require.Equal(t, "hunter2", res.Flat["password"])
	require.Equal(t, "sk-test-12345", res.Flat["api_key"])
}

func TestEncrypt_NoKeysErrors(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.Encrypt(context.Background(), sopswrap.EncryptInput{
		Plaintext: []byte("k: v\n"),
		Format:    sopswrap.FormatYAML,
		Rules:     auth.CreationRules{},
	})
	require.Error(t, err)
}

func TestEncrypt_EncryptedRegexHonored(t *testing.T) {
	t.Parallel()
	pub := testAgeRecipient(t)
	plain := []byte("public: world\nsecret: hunter2\n")

	enc, err := sopswrap.Encrypt(context.Background(), sopswrap.EncryptInput{
		Plaintext: plain,
		Format:    sopswrap.FormatYAML,
		Rules: auth.CreationRules{
			AgeRecipients:  []string{pub},
			EncryptedRegex: "^secret$",
		},
	})
	require.NoError(t, err)
	// `public` should remain in cleartext in the encrypted output; `secret` should not.
	require.Contains(t, string(enc.Ciphertext), "public: world",
		"keys not matching encrypted_regex must remain plaintext")
	require.NotContains(t, string(enc.Ciphertext), "hunter2",
		"keys matching encrypted_regex must be encrypted")
}
