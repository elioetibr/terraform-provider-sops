package auth_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider/auth"
)

func TestMerge_EmptyPerCallReturnsProvider(t *testing.T) {
	t.Parallel()
	provider := auth.Config{
		AWS: auth.AWSConfig{Profile: "prod", Region: "us-east-1"},
	}
	out := auth.Merge(provider, auth.Config{})
	require.Equal(t, "prod", out.AWS.Profile)
	require.Equal(t, "us-east-1", out.AWS.Region)
}

func TestMerge_PerCallOverridesLeafField(t *testing.T) {
	t.Parallel()
	provider := auth.Config{
		AWS: auth.AWSConfig{Profile: "prod", Region: "us-east-1"},
	}
	perCall := auth.Config{
		AWS: auth.AWSConfig{Profile: "dev"},
	}
	out := auth.Merge(provider, perCall)
	require.Equal(t, "dev", out.AWS.Profile, "per-call profile must win")
	require.Equal(t, "us-east-1", out.AWS.Region, "provider region must survive")
}

func TestMerge_AssumeRoleReplacedAtomically(t *testing.T) {
	t.Parallel()
	provider := auth.Config{
		AWS: auth.AWSConfig{
			Profile: "prod",
			AssumeRole: &auth.AWSAssumeRole{
				RoleARN:     "arn:aws:iam::111:role/r1",
				SessionName: "provider-session",
				Duration:    time.Hour,
			},
		},
	}
	perCall := auth.Config{
		AWS: auth.AWSConfig{
			AssumeRole: &auth.AWSAssumeRole{RoleARN: "arn:aws:iam::222:role/r2"},
		},
	}
	out := auth.Merge(provider, perCall)
	require.NotNil(t, out.AWS.AssumeRole)
	require.Equal(t, "arn:aws:iam::222:role/r2", out.AWS.AssumeRole.RoleARN)
	require.Empty(t, out.AWS.AssumeRole.SessionName,
		"AssumeRole is replaced atomically; sub-fields do not merge")
}

func TestMerge_SharedConfigFilesPerCallWinsAtomically(t *testing.T) {
	t.Parallel()
	provider := auth.Config{AWS: auth.AWSConfig{SharedConfigFiles: []string{"/p/c"}}}
	perCall := auth.Config{AWS: auth.AWSConfig{SharedConfigFiles: []string{"/q/c"}}}
	out := auth.Merge(provider, perCall)
	require.Equal(t, []string{"/q/c"}, out.AWS.SharedConfigFiles)
}

func TestMerge_AzureBoolOverride(t *testing.T) {
	t.Parallel()
	provider := auth.Config{Azure: auth.AzureConfig{UseMSI: true}}
	perCall := auth.Config{Azure: auth.AzureConfig{UseOIDC: true}}
	out := auth.Merge(provider, perCall)
	require.True(t, out.Azure.UseMSI)
	require.True(t, out.Azure.UseOIDC)
}

func TestMerge_AzureBoolExplicitFalseDoesNotZeroProvider(t *testing.T) {
	t.Parallel()
	provider := auth.Config{Azure: auth.AzureConfig{UseMSI: true}}
	perCall := auth.Config{} // UseMSI defaults to false
	out := auth.Merge(provider, perCall)
	require.True(t, out.Azure.UseMSI, "absent per-call bool must not zero provider")
}
