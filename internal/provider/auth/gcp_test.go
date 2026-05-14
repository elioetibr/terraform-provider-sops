package auth_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

func TestGCPModelToConfig_AllFields(t *testing.T) {
	t.Parallel()
	m := &auth.GCPModel{
		Credentials:               types.StringValue(`{"type":"service_account"}`),
		CredentialsFile:           types.StringValue("/path/to/sa.json"),
		ImpersonateServiceAccount: types.StringValue("sops@project.iam.gserviceaccount.com"),
		QuotaProject:              types.StringValue("my-billing"),
	}
	cfg, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError(), diags.Errors())
	require.Equal(t, `{"type":"service_account"}`, cfg.Credentials)
	require.Equal(t, "/path/to/sa.json", cfg.CredentialsFile)
	require.Equal(t, "sops@project.iam.gserviceaccount.com", cfg.ImpersonateServiceAccount)
	require.Equal(t, "my-billing", cfg.QuotaProject)
}

func TestGCPModelToConfig_NilSafe(t *testing.T) {
	t.Parallel()
	var m *auth.GCPModel
	cfg, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError())
	require.Empty(t, cfg.Credentials)
}
