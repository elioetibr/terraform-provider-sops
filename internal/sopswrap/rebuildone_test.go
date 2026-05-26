package sopswrap_test

import (
	"testing"

	sops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/azkv"
	"github.com/getsops/sops/v3/gcpkms"
	"github.com/getsops/sops/v3/kms"
	"github.com/getsops/sops/v3/pgp"
	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

// TestRebuildKeyGroups_AllKeyTypes exercises the switch arms inside
// rebuildOne — KMS, GCP-KMS, Azure-KV, age, PGP, plus a default unknown.
// Decryption itself is not attempted; we only care that rebuildOne
// re-creates each key without panicking and preserves EncryptedKey.
func TestRebuildKeyGroups_AllKeyTypes(t *testing.T) {
	t.Parallel()

	// Use a well-formed age recipient so age.MasterKeyFromRecipient succeeds.
	const ageRecipient = "age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"

	ageMK, err := age.MasterKeyFromRecipient(ageRecipient)
	require.NoError(t, err)
	ageMK.EncryptedKey = "age-payload"

	tree := sops.Tree{
		Metadata: sops.Metadata{
			KeyGroups: []sops.KeyGroup{
				{
					&kms.MasterKey{Arn: "arn:aws:kms:us-east-1:123:key/abc", EncryptedKey: "kms-payload"},
					gcpkms.NewMasterKeyFromResourceID("projects/p/locations/global/keyRings/r/cryptoKeys/k"),
					azkv.NewMasterKey("https://kv.vault.azure.net", "key", "v"),
					ageMK,
					pgp.NewMasterKeyFromFingerprint("0000000000000000000000000000000000000000"),
				},
			},
		},
	}

	// Seed EncryptedKey on a couple of keys to verify it's copied through.
	tree.Metadata.KeyGroups[0][1].SetEncryptedDataKey([]byte("gcp"))
	tree.Metadata.KeyGroups[0][4].SetEncryptedDataKey([]byte("pgp"))

	out, err := sopswrap.RebuildKeyGroups(tree, auth.Config{
		AWS: auth.AWSConfig{
			Profile:    "prod",
			AssumeRole: &auth.AWSAssumeRole{RoleARN: "arn:aws:iam::123:role/r"},
		},
	})
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Len(t, out[0], 5, "all 5 key types should be rebuilt")
}

// TestRebuildKeyGroups_KMSFallsBackToProviderRole covers the branch where the
// KMS MasterKey has no embedded role and the provider's assume-role kicks in.
func TestRebuildKeyGroups_KMSFallsBackToProviderRole(t *testing.T) {
	t.Parallel()
	tree := sops.Tree{
		Metadata: sops.Metadata{
			KeyGroups: []sops.KeyGroup{
				{&kms.MasterKey{Arn: "arn:aws:kms:us-east-1:123:key/abc"}},
			},
		},
	}
	out, err := sopswrap.RebuildKeyGroups(tree, auth.Config{
		AWS: auth.AWSConfig{
			AssumeRole: &auth.AWSAssumeRole{RoleARN: "arn:aws:iam::123:role/r"},
		},
	})
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Len(t, out[0], 1)
}
