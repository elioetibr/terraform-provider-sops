package auth_test

import (
	"testing"

	provschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

// TestCreationRulesProviderBlockSchema asserts the schema is well-formed and
// declares every attribute the resource-block variant carries — they must
// stay in sync.
func TestCreationRulesProviderBlockSchema(t *testing.T) {
	t.Parallel()
	block := auth.CreationRulesProviderBlockSchema()
	single, ok := block.(provschema.SingleNestedBlock)
	require.True(t, ok, "expected SingleNestedBlock")
	require.NotEmpty(t, single.Description)

	want := []string{
		"kms_arns", "gcp_kms_resources", "azure_kv_keys",
		"age_recipients", "pgp_fingerprints",
		"encrypted_regex", "unencrypted_regex",
		"encrypted_suffix", "unencrypted_suffix",
		"threshold",
	}
	for _, key := range want {
		_, present := single.Attributes[key]
		require.True(t, present, "provider creation_rules schema must include %q", key)
	}
}
