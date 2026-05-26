package auth_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

// TestMergeAWS_AllSubFields walks every per-call override branch in mergeAWS
// so each leaf-comparison line is exercised at least once.
func TestMergeAWS_AllSubFields(t *testing.T) {
	t.Parallel()
	prov := auth.AWSConfig{
		Profile:                "prov",
		Region:                 "us-east-1",
		SharedConfigFiles:      []string{"/p/cfg"},
		SharedCredentialsFiles: []string{"/p/creds"},
		Env:                    map[string]string{"prov_only": "1"},
	}
	per := auth.AWSConfig{
		Region:                 "eu-west-1",
		SharedCredentialsFiles: []string{"/q/creds"},
		Env:                    map[string]string{"per_only": "1", "prov_only": "overridden"},
		AssumeRole:             &auth.AWSAssumeRole{RoleARN: "arn:role/x"},
	}
	out := auth.Merge(auth.Config{AWS: prov}, auth.Config{AWS: per})
	require.Equal(t, "prov", out.AWS.Profile, "profile preserved")
	require.Equal(t, "eu-west-1", out.AWS.Region, "per-call region wins")
	require.Equal(t, []string{"/p/cfg"}, out.AWS.SharedConfigFiles, "SharedConfigFiles preserved")
	require.Equal(t, []string{"/q/creds"}, out.AWS.SharedCredentialsFiles, "SharedCredentialsFiles overridden atomically")
	require.Equal(t, "1", out.AWS.Env["per_only"])
	require.Equal(t, "overridden", out.AWS.Env["prov_only"], "per-call env value wins")
	require.NotNil(t, out.AWS.AssumeRole)
}

// TestMergeAWS_EnvAllocatedWhenProviderNil exercises the branch where the
// provider has no Env map and a per-call one needs to be merged in.
func TestMergeAWS_EnvAllocatedWhenProviderNil(t *testing.T) {
	t.Parallel()
	out := auth.Merge(
		auth.Config{AWS: auth.AWSConfig{Profile: "p"}},
		auth.Config{AWS: auth.AWSConfig{Env: map[string]string{"AWS_REGION": "x"}}},
	)
	require.Equal(t, "x", out.AWS.Env["AWS_REGION"])
}

func TestMergeGCP_AllSubFields(t *testing.T) {
	t.Parallel()
	prov := auth.GCPConfig{
		Credentials:               "p-creds",
		CredentialsFile:           "/p/creds",
		ImpersonateServiceAccount: "p-sa",
		QuotaProject:              "p-quota",
	}
	per := auth.GCPConfig{
		Credentials:               "c-creds",
		CredentialsFile:           "/c/creds",
		ImpersonateServiceAccount: "c-sa",
		QuotaProject:              "c-quota",
	}
	out := auth.Merge(auth.Config{GCP: prov}, auth.Config{GCP: per})
	require.Equal(t, "c-creds", out.GCP.Credentials)
	require.Equal(t, "/c/creds", out.GCP.CredentialsFile)
	require.Equal(t, "c-sa", out.GCP.ImpersonateServiceAccount)
	require.Equal(t, "c-quota", out.GCP.QuotaProject)
}

func TestMergeAzure_AllSubFields(t *testing.T) {
	t.Parallel()
	prov := auth.AzureConfig{TenantID: "p-tenant", ClientID: "p-client", ClientSecret: "p-secret"}
	per := auth.AzureConfig{
		TenantID:            "c-tenant",
		ClientID:            "c-client",
		ClientSecret:        "c-secret",
		UseOIDC:             true,
		UseWorkloadIdentity: true,
		UseCLI:              true,
	}
	out := auth.Merge(auth.Config{Azure: prov}, auth.Config{Azure: per})
	require.Equal(t, "c-tenant", out.Azure.TenantID)
	require.Equal(t, "c-client", out.Azure.ClientID)
	require.Equal(t, "c-secret", out.Azure.ClientSecret)
	require.True(t, out.Azure.UseOIDC)
	require.True(t, out.Azure.UseWorkloadIdentity)
	require.True(t, out.Azure.UseCLI)
}

func TestMergeAge_AllSubFields(t *testing.T) {
	t.Parallel()
	prov := auth.AgeConfig{Key: "p-key", KeyFile: "/p/key", KeyCommand: "p-cmd", SSHPrivateKeyFile: "/p/ssh"}
	per := auth.AgeConfig{Key: "c-key", KeyFile: "/c/key", KeyCommand: "c-cmd", SSHPrivateKeyFile: "/c/ssh"}
	out := auth.Merge(auth.Config{Age: prov}, auth.Config{Age: per})
	require.Equal(t, "c-key", out.Age.Key)
	require.Equal(t, "/c/key", out.Age.KeyFile)
	require.Equal(t, "c-cmd", out.Age.KeyCommand)
	require.Equal(t, "/c/ssh", out.Age.SSHPrivateKeyFile)
}

func TestMergePGP_AllSubFields(t *testing.T) {
	t.Parallel()
	prov := auth.PGPConfig{GnupgHome: "/p/gpg"}
	per := auth.PGPConfig{GnupgHome: "/c/gpg"}
	out := auth.Merge(auth.Config{PGP: prov}, auth.Config{PGP: per})
	require.Equal(t, "/c/gpg", out.PGP.GnupgHome)
}

func TestMerge_ConcurrencyLimitPerCallWins(t *testing.T) {
	t.Parallel()
	out := auth.Merge(
		auth.Config{ConcurrencyLimit: 4},
		auth.Config{ConcurrencyLimit: 8},
	)
	require.Equal(t, 8, out.ConcurrencyLimit)
}
