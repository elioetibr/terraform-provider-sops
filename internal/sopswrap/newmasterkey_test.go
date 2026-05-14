package sopswrap_test

import (
	"testing"

	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/kms"
	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

func TestBuildMasterKeysFromRules_AgeOnly(t *testing.T) {
	t.Parallel()
	rules := auth.CreationRules{
		AgeRecipients: []string{"age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"},
	}
	groups, err := sopswrap.BuildMasterKeysFromRules(rules, auth.Config{})
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Len(t, groups[0], 1)
	_, ok := groups[0][0].(*age.MasterKey)
	require.True(t, ok)
}

func TestBuildMasterKeysFromRules_KMSWithProfile(t *testing.T) {
	t.Parallel()
	rules := auth.CreationRules{
		KMSARNs: []string{"arn:aws:kms:us-east-1:123:key/abc"},
	}
	cfg := auth.Config{
		AWS: auth.AWSConfig{Profile: "production-sre"},
	}
	groups, err := sopswrap.BuildMasterKeysFromRules(rules, cfg)
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Len(t, groups[0], 1)
	k, ok := groups[0][0].(*kms.MasterKey)
	require.True(t, ok)
	require.Equal(t, "arn:aws:kms:us-east-1:123:key/abc", k.Arn)
	require.Equal(t, "production-sre", k.AwsProfile,
		"AWS profile must be injected from auth.Config (the headline feature)")
}

func TestBuildMasterKeysFromRules_KMSWithAssumeRole(t *testing.T) {
	t.Parallel()
	rules := auth.CreationRules{
		KMSARNs: []string{"arn:aws:kms:us-east-1:123:key/abc"},
	}
	cfg := auth.Config{
		AWS: auth.AWSConfig{
			Profile:    "production-sre",
			AssumeRole: &auth.AWSAssumeRole{RoleARN: "arn:aws:iam::123:role/sops-writer"},
		},
	}
	groups, err := sopswrap.BuildMasterKeysFromRules(rules, cfg)
	require.NoError(t, err)
	k := groups[0][0].(*kms.MasterKey)
	require.Equal(t, "arn:aws:iam::123:role/sops-writer", k.Role)
	require.Equal(t, "production-sre", k.AwsProfile)
}

func TestBuildMasterKeysFromRules_Empty(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.BuildMasterKeysFromRules(auth.CreationRules{}, auth.Config{})
	require.Error(t, err, "empty rules must error")
}

func TestBuildMasterKeysFromRules_MixedSources(t *testing.T) {
	t.Parallel()
	// All recipients land in ONE key group. Threshold semantics live on the group.
	rules := auth.CreationRules{
		KMSARNs:       []string{"arn:aws:kms:us-east-1:1:key/a"},
		AgeRecipients: []string{"age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"},
	}
	groups, err := sopswrap.BuildMasterKeysFromRules(rules, auth.Config{})
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Len(t, groups[0], 2, "kms + age in the same group")
}
