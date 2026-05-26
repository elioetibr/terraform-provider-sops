package sopswrap_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

// canceled returns a context that is already canceled — for testing the
// semaphore-acquire error branch in Encrypt/Decrypt/UpdateKeys.
func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestEncrypt_CanceledContext(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.Encrypt(canceled(), sopswrap.EncryptInput{
		Plaintext: []byte("k: v\n"),
		Format:    sopswrap.FormatYAML,
		Rules:     auth.CreationRules{AgeRecipients: []string{"age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"}},
	})
	require.Error(t, err)
}

func TestDecrypt_CanceledContext(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.Decrypt(canceled(), sopswrap.DecryptInput{
		Source: []byte("anything"),
		Format: sopswrap.FormatYAML,
	})
	require.Error(t, err)
}

func TestUpdateKeys_CanceledContext(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.UpdateKeys(canceled(), sopswrap.UpdateKeysInput{
		Source: []byte("anything"),
		Format: sopswrap.FormatYAML,
	})
	require.Error(t, err)
}

// TestDecrypt_NoKeyMaterial uses the real encrypted fixture but with no
// SOPS_AGE_KEY_FILE set — exercises decrypt.go GetDataKeyWithKeyServices error.
func TestDecrypt_NoKeyMaterial(t *testing.T) {
	// No t.Parallel — manipulating env.
	// Ensure SOPS_AGE_KEY_FILE is unset.
	prev, hadPrev := os.LookupEnv("SOPS_AGE_KEY_FILE")
	require.NoError(t, os.Unsetenv("SOPS_AGE_KEY_FILE"))
	t.Cleanup(func() {
		if hadPrev {
			_ = os.Setenv("SOPS_AGE_KEY_FILE", prev)
		} else {
			_ = os.Unsetenv("SOPS_AGE_KEY_FILE")
		}
	})
	prevKey, hadPrevKey := os.LookupEnv("SOPS_AGE_KEY")
	require.NoError(t, os.Unsetenv("SOPS_AGE_KEY"))
	t.Cleanup(func() {
		if hadPrevKey {
			_ = os.Setenv("SOPS_AGE_KEY", prevKey)
		} else {
			_ = os.Unsetenv("SOPS_AGE_KEY")
		}
	})

	src, err := os.ReadFile(absTestdata(t, "secrets.yaml"))
	require.NoError(t, err)

	_, err = sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: src,
		Format: sopswrap.FormatYAML,
	})
	require.Error(t, err, "without age key material, GetDataKey must fail")
}

// TestUpdateKeys_NoKeyMaterial: same idea against UpdateKeys —
// covers updatekeys.go GetDataKey error path.
func TestUpdateKeys_NoKeyMaterial(t *testing.T) {
	prev, hadPrev := os.LookupEnv("SOPS_AGE_KEY_FILE")
	require.NoError(t, os.Unsetenv("SOPS_AGE_KEY_FILE"))
	t.Cleanup(func() {
		if hadPrev {
			_ = os.Setenv("SOPS_AGE_KEY_FILE", prev)
		} else {
			_ = os.Unsetenv("SOPS_AGE_KEY_FILE")
		}
	})
	prevKey, hadPrevKey := os.LookupEnv("SOPS_AGE_KEY")
	require.NoError(t, os.Unsetenv("SOPS_AGE_KEY"))
	t.Cleanup(func() {
		if hadPrevKey {
			_ = os.Setenv("SOPS_AGE_KEY", prevKey)
		} else {
			_ = os.Unsetenv("SOPS_AGE_KEY")
		}
	})

	src, err := os.ReadFile(absTestdata(t, "secrets.yaml"))
	require.NoError(t, err)

	_, err = sopswrap.UpdateKeys(context.Background(), sopswrap.UpdateKeysInput{
		Source:   src,
		Format:   sopswrap.FormatYAML,
		NewRules: auth.CreationRules{AgeRecipients: []string{"age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"}},
	})
	require.Error(t, err, "without age key material, UpdateKeys must fail at GetDataKey")
}

// TestUpdateKeys_EmptyNewRules: decrypt succeeds, but BuildMasterKeysFromRules
// errors because NewRules has no key source. Covers updatekeys.go line 66.
func TestUpdateKeys_EmptyNewRules(t *testing.T) {
	// Set the age key so initial decrypt succeeds.
	t.Setenv("SOPS_AGE_KEY_FILE", absTestdata(t, "age-key.txt"))

	src, err := os.ReadFile(absTestdata(t, "secrets.yaml"))
	require.NoError(t, err)

	_, err = sopswrap.UpdateKeys(context.Background(), sopswrap.UpdateKeysInput{
		Source:   src,
		Format:   sopswrap.FormatYAML,
		NewRules: auth.CreationRules{}, // no keys → BuildMasterKeysFromRules errors
	})
	require.Error(t, err)
}

// TestEncrypt_MalformedJSONErrors: empty plaintext with JSON format must
// fail at store.LoadPlainFile. Covers encrypt.go line 53.
func TestEncrypt_MalformedJSONErrors(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.Encrypt(context.Background(), sopswrap.EncryptInput{
		Plaintext: []byte("not valid json at all }"),
		Format:    sopswrap.FormatJSON,
		Rules:     auth.CreationRules{AgeRecipients: []string{"age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"}},
	})
	require.Error(t, err)
}

// TestEncrypt_FakePGPFingerprint: a syntactically valid but non-existent PGP
// fingerprint passes BuildMasterKeysFromRules (which just constructs the key
// struct) and fails at GenerateDataKey time when gpg can't find the key.
// Covers encrypt.go line 83.
func TestEncrypt_FakePGPFingerprint(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.Encrypt(context.Background(), sopswrap.EncryptInput{
		Plaintext: []byte("k: v\n"),
		Format:    sopswrap.FormatYAML,
		Rules: auth.CreationRules{
			PGPFingerprints: []string{"DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"},
		},
	})
	require.Error(t, err, "fake PGP fingerprint must fail at data-key encrypt")
}

// TestEncrypt_DotenvWithNonKVErrors: a multi-line plaintext where lines lack
// the KEY=VALUE shape required by the dotenv store. Covers another LoadPlainFile
// error path (and may hit EmitPlainFile depending on the store).
func TestEncrypt_DotenvWithNonKVErrors(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.Encrypt(context.Background(), sopswrap.EncryptInput{
		Plaintext: []byte("this is\nnot a key value\npair format"),
		Format:    sopswrap.FormatDotenv,
		Rules:     auth.CreationRules{AgeRecipients: []string{"age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"}},
	})
	require.Error(t, err)
}

// TestEncrypt_BinaryEmptyPlaintext exercises a less-common store path that may
// surface emit/seal branches the YAML path skips.
func TestEncrypt_BinaryEmptyPlaintext(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.Encrypt(context.Background(), sopswrap.EncryptInput{
		Plaintext: []byte{},
		Format:    sopswrap.FormatBinary,
		Rules:     auth.CreationRules{AgeRecipients: []string{"age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"}},
	})
	// We don't require error or success — we just want the code path executed.
	_ = err
}

// TestEncrypt_YAMLAnchorAlias tries YAML with anchor/alias, which historically
// trips up some round-trippers — may surface the EmitPlainFile error branch.
func TestEncrypt_YAMLAnchorAlias(t *testing.T) {
	t.Parallel()
	plain := []byte("defaults: &d\n  k: v\nitems:\n  - <<: *d\n    k2: v2\n")
	_, err := sopswrap.Encrypt(context.Background(), sopswrap.EncryptInput{
		Plaintext: plain,
		Format:    sopswrap.FormatYAML,
		Rules:     auth.CreationRules{AgeRecipients: []string{"age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"}},
	})
	_ = err
}

// TestEncrypt_YAMLTopLevelScalar passes a top-level scalar (not a map). This
// exercises the YAML store's roundtrip path differently from a normal map doc.
func TestEncrypt_YAMLTopLevelScalar(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.Encrypt(context.Background(), sopswrap.EncryptInput{
		Plaintext: []byte("just a scalar\n"),
		Format:    sopswrap.FormatYAML,
		Rules:     auth.CreationRules{AgeRecipients: []string{"age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"}},
	})
	_ = err
}

// TestDecrypt_TamperedCiphertext: valid-looking SOPS file with a tampered
// MAC — should fail at tree.Decrypt step. Covers decrypt.go line 93.
func TestDecrypt_TamperedCiphertext(t *testing.T) {
	t.Setenv("SOPS_AGE_KEY_FILE", absTestdata(t, "age-key.txt"))

	src, err := os.ReadFile(absTestdata(t, "secrets.yaml"))
	require.NoError(t, err)

	// Mutate the first occurrence of a hex value inside the file —
	// the MAC verification step (inside tree.Decrypt) catches arbitrary
	// payload tampering.
	tampered := make([]byte, len(src))
	copy(tampered, src)
	for i := range tampered {
		// Flip a byte well past the YAML header in the encrypted values area.
		if i > len(tampered)/3 && tampered[i] >= 'a' && tampered[i] <= 'f' {
			tampered[i] = 'X'
			break
		}
	}

	_, err = sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: tampered,
		Format: sopswrap.FormatYAML,
	})
	require.Error(t, err)
}
