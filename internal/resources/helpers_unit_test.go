package resources

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

func TestResolveFormat(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		inputType string
		path      string
		want      sopswrap.Format
	}{
		{"explicit-yaml", "yaml", "/anything.txt", sopswrap.Format("yaml")},
		{"explicit-json", "json", "/x", sopswrap.Format("json")},
		{"explicit-binary", "binary", "/x", sopswrap.Format("binary")},
		{"auto-from-yaml-extension", "", "/path/secrets.yaml", sopswrap.FormatFromPath("/path/secrets.yaml")},
		{"auto-from-json-extension", "", "/path/secrets.json", sopswrap.FormatFromPath("/path/secrets.json")},
		{"auto-unknown-extension", "", "/path/notes.md", sopswrap.FormatFromPath("/path/notes.md")},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, resolveFormat(tc.inputType, tc.path))
		})
	}
}

func TestListOfStrings_EmptyAndNonEmpty(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	emptyList := listOfStrings(ctx, nil)
	require.False(t, emptyList.IsNull())
	require.False(t, emptyList.IsUnknown())
	require.Equal(t, 0, len(emptyList.Elements()))

	zeroLen := listOfStrings(ctx, []string{})
	require.Equal(t, 0, len(zeroLen.Elements()))

	populated := listOfStrings(ctx, []string{"a", "b", "c"})
	require.Equal(t, 3, len(populated.Elements()))
}

func TestMetadataAttrTypes_HasExpectedShape(t *testing.T) {
	t.Parallel()
	types := metadataAttrTypes()
	want := []string{
		"lastmodified", "mac", "version",
		"kms_arns", "gcp_kms_resources", "azure_kv_urls",
		"age_recipients", "pgp_fingerprints",
	}
	for _, k := range want {
		_, ok := types[k]
		require.True(t, ok, "metadata schema is missing %q", k)
	}
}

// TestMetadataObjectValue_RoundTrip ensures the Object value built from a
// sopswrap.Metadata can be inspected and matches the schema's attribute set.
func TestMetadataObjectValue_RoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	md := sopswrap.Metadata{
		LastModified:    time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		MAC:             "abc",
		Version:         "3.10.0",
		KMSARNs:         []string{"arn:aws:kms:us-east-1:1:key/k"},
		AgeRecipients:   []string{"age1xyz"},
		PGPFingerprints: []string{"DEADBEEF"},
	}
	obj := metadataObjectValue(ctx, md)
	require.False(t, obj.IsNull())
	require.False(t, obj.IsUnknown())
	require.Equal(t, metadataAttrTypes(), obj.AttributeTypes(ctx))
}
