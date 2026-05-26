package sopswrap_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

func TestDecrypt_UnknownFormatErrors(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: []byte("anything"),
		Format: sopswrap.Format("not-a-format"),
	})
	require.Error(t, err)
}

func TestDecrypt_MalformedYAMLErrors(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: []byte("this is\nnot::a sops file\n"),
		Format: sopswrap.Format("yaml"),
	})
	require.Error(t, err)
}

func TestEncrypt_UnknownFormatErrors(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.Encrypt(context.Background(), sopswrap.EncryptInput{
		Plaintext: []byte("k: v\n"),
		Format:    sopswrap.Format("not-a-format"),
		Rules: auth.CreationRules{
			AgeRecipients: []string{"age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"},
		},
	})
	require.Error(t, err)
}

func TestEncrypt_BadAgeRecipientErrors(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.Encrypt(context.Background(), sopswrap.EncryptInput{
		Plaintext: []byte("k: v\n"),
		Format:    sopswrap.Format("yaml"),
		Rules:     auth.CreationRules{AgeRecipients: []string{"not-a-real-recipient"}},
	})
	require.Error(t, err)
}

func TestUpdateKeys_UnknownFormatErrors(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.UpdateKeys(context.Background(), sopswrap.UpdateKeysInput{
		Source: []byte("anything"),
		Format: sopswrap.Format("not-a-format"),
	})
	require.Error(t, err)
}

func TestUpdateKeys_MalformedCiphertextErrors(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.UpdateKeys(context.Background(), sopswrap.UpdateKeysInput{
		Source: []byte("definitely:\n  not: a sops file\n"),
		Format: sopswrap.Format("yaml"),
	})
	require.Error(t, err)
}

func TestSemaphore_AcquireCanceled(t *testing.T) {
	t.Parallel()
	sem := sopswrap.NewSemaphore(1)
	// Saturate the semaphore.
	rel, err := sem.Acquire(context.Background())
	require.NoError(t, err)
	defer rel()

	// Second Acquire on a canceled context must return without blocking.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = sem.Acquire(ctx)
	require.Error(t, err)
}
