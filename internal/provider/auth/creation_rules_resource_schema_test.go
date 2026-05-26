package auth_test

import (
	"testing"

	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

// TestCreationRulesResourceBlockSchema mirrors the provider-block schema test —
// both variants must declare the same attribute surface.
func TestCreationRulesResourceBlockSchema(t *testing.T) {
	t.Parallel()
	block := auth.CreationRulesResourceBlockSchema()
	single, ok := block.(rschema.SingleNestedBlock)
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
		require.True(t, present, "resource creation_rules schema must include %q", key)
	}
}
