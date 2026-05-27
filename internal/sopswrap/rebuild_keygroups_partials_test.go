package sopswrap_test

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

// tamperedFixtureBadAgeRecipient loads the canonical secrets.yaml fixture and
// rewrites the embedded age recipient to a syntactically invalid string. The
// resulting bytes parse as a sops envelope (so LoadEncryptedFile succeeds) but
// fail at RebuildKeyGroups when rebuildOne hits the age case.
func tamperedFixtureBadAgeRecipient(t *testing.T) []byte {
	t.Helper()
	src, err := os.ReadFile(absTestdata(t, "secrets.yaml"))
	require.NoError(t, err)
	tampered := bytes.Replace(src,
		[]byte("age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"),
		[]byte("not-a-valid-age-recipient-bech32-string"), 1)
	require.NotEqual(t, src, tampered, "tamper must change the bytes")
	return tampered
}

// TestDecrypt_RebuildKeyGroupsErr covers the partial+miss pair in decrypt.go
// at lines 82-83 (the `RebuildKeyGroups err` branch).
func TestDecrypt_RebuildKeyGroupsErr(t *testing.T) {
	t.Parallel()
	tampered := tamperedFixtureBadAgeRecipient(t)
	_, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: tampered,
		Format: sopswrap.FormatYAML,
	})
	require.Error(t, err, "tampered age recipient must surface as RebuildKeyGroups failure")
	require.Contains(t, err.Error(), "rebuild key groups",
		"the wrapping error must include 'rebuild key groups' from decrypt.go:83")
}

// TestUpdateKeys_RebuildKeyGroupsErr covers the partial+miss pair in
// updatekeys.go at lines 53-54.
func TestUpdateKeys_RebuildKeyGroupsErr(t *testing.T) {
	t.Parallel()
	tampered := tamperedFixtureBadAgeRecipient(t)
	_, err := sopswrap.UpdateKeys(context.Background(), sopswrap.UpdateKeysInput{
		Source: tampered,
		Format: sopswrap.FormatYAML,
		NewRules: auth.CreationRules{
			AgeRecipients: []string{"age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"},
		},
	})
	require.Error(t, err, "tampered age recipient must fail RebuildKeyGroups in UpdateKeys")
}

// TestUpdateKeys_UpdateMasterKeysErr covers the partial+miss pair in
// updatekeys.go at lines 74-75 (the `UpdateMasterKeysWithKeyServices errs`
// branch). After a successful decrypt of the existing tree, the new master-key
// list includes a PGP fingerprint that the local gpg cannot encrypt to (the
// key is not in any keyring), so the re-encrypt step returns errors.
func TestUpdateKeys_UpdateMasterKeysErr(t *testing.T) {
	// No t.Parallel — sets env via setAgeEnv.
	setAgeEnv(t)

	src, err := os.ReadFile(absTestdata(t, "secrets.yaml"))
	require.NoError(t, err)

	_, err = sopswrap.UpdateKeys(context.Background(), sopswrap.UpdateKeysInput{
		Source: src,
		Format: sopswrap.FormatYAML,
		NewRules: auth.CreationRules{
			// Syntactically valid fingerprint that does not exist in any local
			// keyring — UpdateMasterKeysWithKeyServices errors when it tries
			// to re-encrypt the data key to it.
			PGPFingerprints: []string{"DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"},
		},
	})
	require.Error(t, err, "fake PGP fingerprint in NewRules must fail at re-encrypt step")
}
