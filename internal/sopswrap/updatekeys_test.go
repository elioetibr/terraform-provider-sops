package sopswrap_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

func TestUpdateKeys_AddsNewRecipient(t *testing.T) {
	// NOTE: no t.Parallel() — this test calls t.Setenv, which is incompatible
	// with t.Parallel() in Go 1.21+.
	pub := testAgeRecipient(t)
	// Start with a file encrypted to pub.
	enc, err := sopswrap.Encrypt(context.Background(), sopswrap.EncryptInput{
		Plaintext: []byte("k: v\n"),
		Format:    sopswrap.FormatYAML,
		Rules:     auth.CreationRules{AgeRecipients: []string{pub}},
	})
	require.NoError(t, err)
	t.Setenv("SOPS_AGE_KEY_FILE", absTestdata(t, "age-key.txt"))

	// New recipient set: original + an additional age recipient.
	newPub := "age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"
	upd, err := sopswrap.UpdateKeys(context.Background(), sopswrap.UpdateKeysInput{
		Source: enc.Ciphertext,
		Format: sopswrap.FormatYAML,
		NewRules: auth.CreationRules{
			AgeRecipients: []string{pub, newPub},
		},
	})
	require.NoError(t, err)
	require.NotEqual(t, enc.Ciphertext, upd.Ciphertext,
		"updated file must differ from original (different encrypted data key)")

	// New file decrypts successfully with the original key file.
	res, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: upd.Ciphertext,
		Format: sopswrap.FormatYAML,
	})
	require.NoError(t, err)
	require.Equal(t, "v", res.Flat["k"])
}

func TestUpdateKeys_KeepsPlaintextStable(t *testing.T) {
	// NOTE: no t.Parallel() — this test calls t.Setenv, which is incompatible
	// with t.Parallel() in Go 1.21+.
	pub := testAgeRecipient(t)
	enc, err := sopswrap.Encrypt(context.Background(), sopswrap.EncryptInput{
		Plaintext: []byte("password: hunter2\n"),
		Format:    sopswrap.FormatYAML,
		Rules:     auth.CreationRules{AgeRecipients: []string{pub}},
	})
	require.NoError(t, err)
	t.Setenv("SOPS_AGE_KEY_FILE", absTestdata(t, "age-key.txt"))

	upd, err := sopswrap.UpdateKeys(context.Background(), sopswrap.UpdateKeysInput{
		Source: enc.Ciphertext,
		Format: sopswrap.FormatYAML,
		NewRules: auth.CreationRules{
			AgeRecipients: []string{pub, "age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"},
		},
	})
	require.NoError(t, err)

	// Plaintext must be unchanged.
	res, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: upd.Ciphertext,
		Format: sopswrap.FormatYAML,
	})
	require.NoError(t, err)
	require.Equal(t, "hunter2", res.Flat["password"])
}
