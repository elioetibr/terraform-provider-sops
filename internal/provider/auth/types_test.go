package auth_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

func TestConfigZeroValue(t *testing.T) {
	t.Parallel()
	var cfg auth.Config
	require.Empty(t, cfg.AWS.Profile)
	require.Empty(t, cfg.GCP.CredentialsFile)
	require.Empty(t, cfg.Azure.TenantID)
	require.Empty(t, cfg.Age.KeyFile)
	require.Empty(t, cfg.PGP.GnupgHome)
}

func TestConfigAssumeRoleNested(t *testing.T) {
	t.Parallel()
	cfg := auth.Config{
		AWS: auth.AWSConfig{
			Profile: "p",
			AssumeRole: &auth.AWSAssumeRole{
				RoleARN: "arn:aws:iam::123:role/r",
			},
		},
	}
	require.Equal(t, "p", cfg.AWS.Profile)
	require.NotNil(t, cfg.AWS.AssumeRole)
	require.Equal(t, "arn:aws:iam::123:role/r", cfg.AWS.AssumeRole.RoleARN)
}
