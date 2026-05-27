package sopswrap_test

import (
	"testing"

	sops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/keys"
	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

// TestRebuildKeyGroups_InvalidAgeRecipientErrors covers two correlated branches
// in masterkey.go that codecov reports as partial+miss pairs:
//
//   - rebuildOne (line 73-77, age case): age.MasterKeyFromRecipient(k.Recipient)
//     errors when the recipient string is malformed.
//   - RebuildKeyGroups (line 32-35, outer loop): the per-key error returned by
//     rebuildOne is wrapped with the master-key type and propagated.
//
// We construct an age.MasterKey directly with a syntactically invalid recipient
// (the constructor would reject this — we bypass it by setting the field) so
// rebuildOne hits its age-decode-failure path.
func TestRebuildKeyGroups_InvalidAgeRecipientErrors(t *testing.T) {
	t.Parallel()
	tree := sops.Tree{
		Metadata: sops.Metadata{
			KeyGroups: []sops.KeyGroup{{
				&age.MasterKey{Recipient: "not-a-valid-age-recipient"},
			}},
		},
	}
	_, err := sopswrap.RebuildKeyGroups(tree, auth.Config{})
	require.Error(t, err, "an invalid age recipient must propagate from rebuildOne to RebuildKeyGroups")
	require.Contains(t, err.Error(), "rebuilding",
		"the wrapping error must include the 'rebuilding %T' prefix from masterkey.go:34")
}

// stubMasterKey embeds *age.MasterKey so it satisfies the keys.MasterKey
// interface (inheriting all of age's methods) but its dynamic type is
// *stubMasterKey, not *age.MasterKey. That makes rebuildOne's type-switch fall
// through to the `default` case (masterkey.go:89-91) — the only branch the
// existing tests never reach.
type stubMasterKey struct {
	*age.MasterKey
}

// Static assertion: stubMasterKey satisfies the interface.
var _ keys.MasterKey = (*stubMasterKey)(nil)

// TestRebuildKeyGroups_DefaultCasePassthrough covers the rebuildOne default
// case (line 89-91 in masterkey.go) — an unknown master-key type is returned
// unchanged. Required for forward compatibility when sops adds new key types.
func TestRebuildKeyGroups_DefaultCasePassthrough(t *testing.T) {
	t.Parallel()
	// Build a real age master key (so the embedded methods work) then wrap
	// it so the dynamic type changes.
	inner, err := age.MasterKeyFromRecipient("age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9")
	require.NoError(t, err)
	stub := &stubMasterKey{MasterKey: inner}

	tree := sops.Tree{
		Metadata: sops.Metadata{KeyGroups: []sops.KeyGroup{{stub}}},
	}
	groups, err := sopswrap.RebuildKeyGroups(tree, auth.Config{})
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Len(t, groups[0], 1)

	// Default case returns the original mk unchanged.
	require.Same(t, stub, groups[0][0],
		"unknown master-key types must pass through rebuildOne untouched")
}
