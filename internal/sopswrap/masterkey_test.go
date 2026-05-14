package sopswrap_test

import (
	"testing"

	sops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/kms"
	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

func TestRebuildKeyGroups_InjectsAWSProfile(t *testing.T) {
	t.Parallel()

	origKMS := kms.NewMasterKeyFromArn("arn:aws:kms:us-east-1:123:key/abc", nil, "")
	tree := sops.Tree{
		Metadata: sops.Metadata{
			KeyGroups: []sops.KeyGroup{{origKMS}},
		},
	}

	cfg := auth.Config{
		AWS: auth.AWSConfig{Profile: "production-sre", Region: "us-east-1"},
	}

	groups, err := sopswrap.RebuildKeyGroups(tree, cfg)
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Len(t, groups[0], 1)

	rebuilt, ok := groups[0][0].(*kms.MasterKey)
	require.True(t, ok, "expected kms.MasterKey")
	require.Equal(t, "production-sre", rebuilt.AwsProfile,
		"profile must be injected from auth.Config")
	require.Equal(t, "arn:aws:kms:us-east-1:123:key/abc", rebuilt.Arn)
}

func TestRebuildKeyGroups_PreservesEmbeddedRole(t *testing.T) {
	t.Parallel()
	// File was encrypted by a key with an embedded assume-role ARN.
	// That Role MUST survive rebuild — it is the source of truth from the SOPS file.
	origKMS := kms.NewMasterKey("arn:aws:kms:us-east-1:111:key/abc", "arn:aws:iam::111:role/sops-encrypter", nil)
	tree := sops.Tree{
		Metadata: sops.Metadata{
			KeyGroups: []sops.KeyGroup{{origKMS}},
		},
	}

	// Provider also configures a DIFFERENT assume-role. Embedded role should win.
	cfg := auth.Config{
		AWS: auth.AWSConfig{
			Profile: "production-sre",
			AssumeRole: &auth.AWSAssumeRole{
				RoleARN: "arn:aws:iam::999:role/different",
			},
		},
	}

	groups, err := sopswrap.RebuildKeyGroups(tree, cfg)
	require.NoError(t, err)
	rebuilt := groups[0][0].(*kms.MasterKey)
	require.Equal(t, "arn:aws:iam::111:role/sops-encrypter", rebuilt.Role,
		"embedded Role from SOPS file must survive — it is the source of truth")
	require.Equal(t, "production-sre", rebuilt.AwsProfile)
}

func TestRebuildKeyGroups_AssumeRoleFallbackWhenEmpty(t *testing.T) {
	t.Parallel()
	// File has no embedded role. Fall back to provider-configured assume_role.
	origKMS := kms.NewMasterKey("arn:aws:kms:us-east-1:111:key/abc", "", nil)
	tree := sops.Tree{
		Metadata: sops.Metadata{KeyGroups: []sops.KeyGroup{{origKMS}}},
	}
	cfg := auth.Config{
		AWS: auth.AWSConfig{
			AssumeRole: &auth.AWSAssumeRole{RoleARN: "arn:aws:iam::222:role/fallback"},
		},
	}
	groups, err := sopswrap.RebuildKeyGroups(tree, cfg)
	require.NoError(t, err)
	rebuilt := groups[0][0].(*kms.MasterKey)
	require.Equal(t, "arn:aws:iam::222:role/fallback", rebuilt.Role,
		"empty embedded Role should fall back to provider assume_role")
}

func TestRebuildKeyGroups_AgePassthrough(t *testing.T) {
	t.Parallel()
	ageKey, err := age.MasterKeyFromRecipient("age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9")
	require.NoError(t, err)
	tree := sops.Tree{
		Metadata: sops.Metadata{KeyGroups: []sops.KeyGroup{{ageKey}}},
	}
	groups, err := sopswrap.RebuildKeyGroups(tree, auth.Config{})
	require.NoError(t, err)
	require.Len(t, groups[0], 1)
	rebuilt, ok := groups[0][0].(*age.MasterKey)
	require.True(t, ok)
	require.Equal(t, ageKey.Recipient, rebuilt.Recipient)
}
