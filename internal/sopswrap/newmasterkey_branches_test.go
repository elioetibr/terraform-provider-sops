package sopswrap_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

func TestBuildMasterKeysFromRules_AllRecipientTypes(t *testing.T) {
	t.Parallel()
	rules := auth.CreationRules{
		KMSARNs:         []string{"arn:aws:kms:us-east-1:1:key/k"},
		GCPKMSResources: []string{"projects/p/locations/global/keyRings/r/cryptoKeys/k"},
		AzureKVKeys:     []string{"https://kv.vault.azure.net/keys/key/v"},
		AgeRecipients:   []string{"age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"},
		PGPFingerprints: []string{"DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"},
	}
	cfg := auth.Config{
		AWS: auth.AWSConfig{
			Profile:    "prod",
			AssumeRole: &auth.AWSAssumeRole{RoleARN: "arn:aws:iam::1:role/r"},
		},
	}
	groups, err := sopswrap.BuildMasterKeysFromRules(rules, cfg)
	require.NoError(t, err)
	require.Len(t, groups, 1, "all keys land in a single group")
	require.Len(t, groups[0], 5, "one master key per recipient")
}

func TestBuildMasterKeysFromRules_NoRecipientsErrors(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.BuildMasterKeysFromRules(auth.CreationRules{}, auth.Config{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no recipients")
}

func TestBuildMasterKeysFromRules_InvalidAgeRecipientErrors(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.BuildMasterKeysFromRules(auth.CreationRules{
		AgeRecipients: []string{"definitely-not-bech32"},
	}, auth.Config{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "age recipient")
}

func TestBuildMasterKeysFromRules_InvalidAzureURLErrors(t *testing.T) {
	t.Parallel()
	_, err := sopswrap.BuildMasterKeysFromRules(auth.CreationRules{
		AzureKVKeys: []string{"::not a url::"},
	}, auth.Config{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "azkv parse")
}

func TestBuildMasterKeysFromRules_KMSWithoutAssumeRoleOmitsRole(t *testing.T) {
	t.Parallel()
	rules := auth.CreationRules{KMSARNs: []string{"arn:aws:kms:us-east-1:1:key/k"}}
	groups, err := sopswrap.BuildMasterKeysFromRules(rules, auth.Config{AWS: auth.AWSConfig{Profile: "p"}})
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Len(t, groups[0], 1)
}
