package auth_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/require"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
)

func TestAgeModelToConfig_KeyFile(t *testing.T) {
	t.Parallel()
	m := &auth.AgeModel{KeyFile: types.StringValue("/path/to/keys.txt")}
	cfg, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError())
	require.Equal(t, "/path/to/keys.txt", cfg.KeyFile)
}

func TestAgeModelToConfig_KeyCommand(t *testing.T) {
	t.Parallel()
	m := &auth.AgeModel{KeyCommand: types.StringValue("pass show age/sops")}
	cfg, _ := m.ToConfig(context.Background())
	require.Equal(t, "pass show age/sops", cfg.KeyCommand)
}

func TestAgeModelToConfig_NilSafe(t *testing.T) {
	t.Parallel()
	var m *auth.AgeModel
	_, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError())
}
