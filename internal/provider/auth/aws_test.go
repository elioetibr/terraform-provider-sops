package auth_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

func TestAWSModelToConfig_AllFields(t *testing.T) {
	t.Parallel()
	m := &auth.AWSModel{
		Profile:                types.StringValue("prod"),
		Region:                 types.StringValue("us-east-1"),
		SharedConfigFiles:      listOfStrings(t, "/p/config"),
		SharedCredentialsFiles: listOfStrings(t, "/p/credentials"),
		Env:                    mapOfStrings(t, map[string]string{"AWS_SDK_LOAD_CONFIG": "1"}),
		AssumeRole: &auth.AWSAssumeRoleModel{
			RoleARN:     types.StringValue("arn:aws:iam::1:role/r"),
			SessionName: types.StringValue("sess"),
			ExternalID:  types.StringValue("ext"),
			Duration:    types.StringValue("1h"),
		},
	}
	cfg, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError(), diags.Errors())
	require.Equal(t, "prod", cfg.Profile)
	require.Equal(t, "us-east-1", cfg.Region)
	require.Equal(t, []string{"/p/config"}, cfg.SharedConfigFiles)
	require.Equal(t, []string{"/p/credentials"}, cfg.SharedCredentialsFiles)
	require.Equal(t, "1", cfg.Env["AWS_SDK_LOAD_CONFIG"])
	require.NotNil(t, cfg.AssumeRole)
	require.Equal(t, "arn:aws:iam::1:role/r", cfg.AssumeRole.RoleARN)
}

func TestAWSModelToConfig_InvalidDuration(t *testing.T) {
	t.Parallel()
	m := &auth.AWSModel{
		AssumeRole: &auth.AWSAssumeRoleModel{Duration: types.StringValue("not-a-duration")},
	}
	_, diags := m.ToConfig(context.Background())
	require.True(t, diags.HasError())
}

func TestAWSModelToConfig_NilSafe(t *testing.T) {
	t.Parallel()
	var m *auth.AWSModel
	cfg, diags := m.ToConfig(context.Background())
	require.False(t, diags.HasError())
	require.Empty(t, cfg.Profile)
}

// helpers
func listOfStrings(t *testing.T, ss ...string) types.List {
	t.Helper()
	vals := make([]attr.Value, len(ss))
	for i, s := range ss {
		vals[i] = types.StringValue(s)
	}
	l, diags := types.ListValue(types.StringType, vals)
	require.False(t, diags.HasError(), diags.Errors())
	return l
}

func mapOfStrings(t *testing.T, m map[string]string) types.Map {
	t.Helper()
	vals := map[string]attr.Value{}
	for k, v := range m {
		vals[k] = types.StringValue(v)
	}
	out, diags := types.MapValue(types.StringType, vals)
	require.False(t, diags.HasError(), diags.Errors())
	return out
}
