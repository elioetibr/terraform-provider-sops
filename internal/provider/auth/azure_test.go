package auth_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/require"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
)

func TestAzureModelToConfig_OIDC(t *testing.T) {
	t.Parallel()
	m := &auth.AzureModel{
		TenantID: types.StringValue("00000000-0000-0000-0000-000000000000"),
		ClientID: types.StringValue("11111111-1111-1111-1111-111111111111"),
		UseOIDC:  types.BoolValue(true),
	}
	cfg, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError(), diags.Errors())
	require.Equal(t, "00000000-0000-0000-0000-000000000000", cfg.TenantID)
	require.True(t, cfg.UseOIDC)
	require.False(t, cfg.UseMSI)
}

func TestAzureModelToConfig_NilSafe(t *testing.T) {
	t.Parallel()
	var m *auth.AzureModel
	_, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError())
}
