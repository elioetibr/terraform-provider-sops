package auth_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

func TestPGPModelToConfig(t *testing.T) {
	t.Parallel()
	m := &auth.PGPModel{GnupgHome: types.StringValue("/home/user/.gnupg")}
	cfg, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError())
	require.Equal(t, "/home/user/.gnupg", cfg.GnupgHome)
}

func TestPGPModelToConfig_NilSafe(t *testing.T) {
	t.Parallel()
	var m *auth.PGPModel
	_, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError())
}
