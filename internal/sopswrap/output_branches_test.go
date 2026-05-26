package sopswrap_test

import (
	"encoding/json"
	"testing"
	"time"

	sops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/azkv"
	"github.com/getsops/sops/v3/gcpkms"
	"github.com/getsops/sops/v3/kms"
	"github.com/getsops/sops/v3/pgp"
	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

// TestExtractMetadata_AllKeyTypes verifies that ExtractMetadata routes each
// MasterKey concrete type into the correct metadata bucket.
func TestExtractMetadata_AllKeyTypes(t *testing.T) {
	t.Parallel()

	ageMK, err := age.MasterKeyFromRecipient(
		"age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9")
	require.NoError(t, err)

	tree := sops.Tree{
		Metadata: sops.Metadata{
			LastModified:              time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
			MessageAuthenticationCode: "MAC",
			Version:                   "3.10.0",
			UnencryptedSuffix:         "_unenc",
			EncryptedSuffix:           "_enc",
			UnencryptedRegex:          "^public$",
			EncryptedRegex:            "^secret$",
			KeyGroups: []sops.KeyGroup{
				{
					&kms.MasterKey{Arn: "arn:aws:kms:us-east-1:1:key/k"},
					gcpkms.NewMasterKeyFromResourceID("projects/p/locations/global/keyRings/r/cryptoKeys/k"),
					azkv.NewMasterKey("https://kv.vault.azure.net", "key", "v"),
					ageMK,
					pgp.NewMasterKeyFromFingerprint("DEADBEEF"),
				},
			},
		},
	}

	md := sopswrap.ExtractMetadata(tree)
	require.Equal(t, "MAC", md.MAC)
	require.Equal(t, "3.10.0", md.Version)
	require.Equal(t, "_unenc", md.UnencryptedSuffix)
	require.Equal(t, "_enc", md.EncryptedSuffix)
	require.Equal(t, "^public$", md.UnencryptedRegex)
	require.Equal(t, "^secret$", md.EncryptedRegex)
	require.Len(t, md.KMSARNs, 1)
	require.Len(t, md.GCPKMSResources, 1)
	require.Len(t, md.AzureKVURLs, 1)
	require.Len(t, md.AgeRecipients, 1)
	require.Len(t, md.PGPFingerprints, 1)
}

func TestExtractMetadata_EmptyKeyGroupsTolerated(t *testing.T) {
	t.Parallel()
	md := sopswrap.ExtractMetadata(sops.Tree{})
	require.Empty(t, md.KMSARNs)
	require.Empty(t, md.AgeRecipients)
}

// TestToJSON_BranchVariants drives toGo through TreeBranches (single +
// multi-doc), TreeBranch, []interface{}, Comment, and primitive leaf paths.
func TestToJSON_BranchVariants(t *testing.T) {
	t.Parallel()

	branches := sops.TreeBranches{
		sops.TreeBranch{
			{Key: "scalar", Value: "value"},
			{Key: "number", Value: 42},
			{Key: "comment-keyed", Value: "skipped-via-comment-key"},
			{Key: sops.Comment{Value: "this top-level key is a comment"}, Value: "ignored"},
			{Key: "nested", Value: sops.TreeBranch{
				{Key: "x", Value: "1"},
			}},
			{Key: "list", Value: []interface{}{
				"a", 1, sops.Comment{Value: "filtered"},
			}},
		},
	}

	out, err := sopswrap.ToJSON(branches)
	require.NoError(t, err)

	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &got))
	require.Equal(t, "value", got["scalar"])
	require.EqualValues(t, 42, got["number"])
	nested, ok := got["nested"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "1", nested["x"])
	list, ok := got["list"].([]interface{})
	require.True(t, ok)
	require.Len(t, list, 2, "Comment item must be filtered out of lists")
}

// TestToJSON_MultiDocBranches covers the rare multi-doc branch of toGo where
// len(TreeBranches) > 1 returns a list.
func TestToJSON_MultiDocBranches(t *testing.T) {
	t.Parallel()
	branches := sops.TreeBranches{
		sops.TreeBranch{{Key: "doc1", Value: "a"}},
		sops.TreeBranch{{Key: "doc2", Value: "b"}},
	}
	out, err := sopswrap.ToJSON(branches)
	require.NoError(t, err)

	var got []map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &got))
	require.Len(t, got, 2)
	require.Equal(t, "a", got[0]["doc1"])
	require.Equal(t, "b", got[1]["doc2"])
}

// TestFlatten_NestedListsAndComments exercises walk()'s branches for
// nested maps, lists with stringified indices, and Comment skipping.
func TestFlatten_NestedListsAndComments(t *testing.T) {
	t.Parallel()
	branches := sops.TreeBranches{
		sops.TreeBranch{
			{Key: "db", Value: sops.TreeBranch{
				{Key: "host", Value: "localhost"},
				{Key: sops.Comment{Value: "internal"}, Value: "ignored"},
			}},
			{Key: "tags", Value: []interface{}{"a", "b"}},
		},
	}
	flat := sopswrap.Flatten(branches)
	require.Equal(t, "localhost", flat["db.host"])
	require.Equal(t, "a", flat["tags.0"])
	require.Equal(t, "b", flat["tags.1"])
}
