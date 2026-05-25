package auth_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

func TestCreationRulesToConfig_AllFields(t *testing.T) {
	t.Parallel()
	m := &auth.CreationRulesModel{
		KMSARNs:           listOf(t, "arn:aws:kms:us-east-1:1:key/abc"),
		GCPKMSResources:   listOf(t, "projects/p/locations/global/keyRings/r/cryptoKeys/k"),
		AzureKVKeys:       listOf(t, "https://kv.vault.azure.net/keys/k/v"),
		AgeRecipients:     listOf(t, "age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"),
		PGPFingerprints:   listOf(t, "FBC7B9E2A4F9289AC0C1D4843D16CEE4A27381B4"),
		EncryptedRegex:    types.StringValue("^(data|stringData)$"),
		UnencryptedRegex:  types.StringValue(""),
		EncryptedSuffix:   types.StringValue(""),
		UnencryptedSuffix: types.StringValue("_unencrypted"),
		Threshold:         types.Int64Value(2),
	}
	cfg, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError(), diags.Errors())
	require.Equal(t, []string{"arn:aws:kms:us-east-1:1:key/abc"}, cfg.KMSARNs)
	require.Equal(t, []string{"age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"}, cfg.AgeRecipients)
	require.Equal(t, "^(data|stringData)$", cfg.EncryptedRegex)
	require.Equal(t, "_unencrypted", cfg.UnencryptedSuffix)
	require.Equal(t, 2, cfg.Threshold)
}

func TestCreationRulesToConfig_NilSafe(t *testing.T) {
	t.Parallel()
	var m *auth.CreationRulesModel
	cfg, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError())
	require.Empty(t, cfg.KMSARNs)
	require.Empty(t, cfg.AgeRecipients)
}

func TestCreationRulesToConfig_RequireAtLeastOneKey(t *testing.T) {
	t.Parallel()
	// Empty creation_rules with no keys at all is a user error.
	m := &auth.CreationRulesModel{}
	_, diags := m.ToConfig(context.Background())
	require.True(t, diags.HasError(),
		"creation_rules with no kms_arns/age_recipients/etc. must error")
}

// helper local to this test file
func listOf(t *testing.T, ss ...string) types.List {
	t.Helper()
	vals := make([]attr.Value, len(ss))
	for i, s := range ss {
		vals[i] = types.StringValue(s)
	}
	l, diags := types.ListValue(types.StringType, vals)
	require.False(t, diags.HasError(), diags.Errors())
	return l
}
