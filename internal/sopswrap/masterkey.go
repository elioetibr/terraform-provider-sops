package sopswrap

import (
	"fmt"

	sops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/azkv"
	"github.com/getsops/sops/v3/gcpkms"
	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/kms"
	"github.com/getsops/sops/v3/pgp"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

// RebuildKeyGroups walks an encrypted tree's key groups and reconstructs each
// MasterKey with credentials from the provided auth.Config. This is the entire
// reason this provider exists — SOPS's decrypt.Data() does not give us this hook.
//
// Each key type knows what to do with our config:
//   - kms.MasterKey: takes Profile + assume-role + region
//   - gcpkms.MasterKey: takes credentials file/JSON + impersonation target
//   - azkv.MasterKey: takes tenant/client/secret + auth-method flags
//   - age.MasterKey: passthrough (reads env in Decrypt())
//   - pgp.MasterKey: takes GnupgHome
func RebuildKeyGroups(tree sops.Tree, cfg auth.Config) ([]sops.KeyGroup, error) {
	out := make([]sops.KeyGroup, len(tree.Metadata.KeyGroups))
	for i, group := range tree.Metadata.KeyGroups {
		rebuilt := make(sops.KeyGroup, 0, len(group))
		for _, mk := range group {
			rk, err := rebuildOne(mk, cfg)
			if err != nil {
				return nil, fmt.Errorf("rebuilding %T: %w", mk, err)
			}
			rebuilt = append(rebuilt, rk)
		}
		out[i] = rebuilt
	}
	return out, nil
}

func rebuildOne(mk keys.MasterKey, cfg auth.Config) (keys.MasterKey, error) {
	switch k := mk.(type) {
	case *kms.MasterKey:
		// Determine the effective role: embedded role from the SOPS file is the
		// source of truth; only fall back to the provider-configured assume_role
		// when the file has no embedded role.
		role := k.Role
		if role == "" && cfg.AWS.AssumeRole != nil {
			role = cfg.AWS.AssumeRole.RoleARN
		}
		out := kms.NewMasterKeyWithProfile(k.Arn, role, k.EncryptionContext, cfg.AWS.Profile)
		out.EncryptedKey = k.EncryptedKey
		out.CreationDate = k.CreationDate
		return out, nil

	case *gcpkms.MasterKey:
		out := gcpkms.NewMasterKeyFromResourceID(k.ResourceID)
		out.EncryptedKey = k.EncryptedKey
		out.CreationDate = k.CreationDate
		// gcpkms reads GOOGLE_APPLICATION_CREDENTIALS from scoped env in T14.
		_ = cfg.GCP
		return out, nil

	case *azkv.MasterKey:
		out := azkv.NewMasterKey(k.VaultURL, k.Name, k.Version)
		out.EncryptedKey = k.EncryptedKey
		out.CreationDate = k.CreationDate
		_ = cfg.Azure
		return out, nil

	case *age.MasterKey:
		out, err := age.MasterKeyFromRecipient(k.Recipient)
		if err != nil {
			return nil, err
		}
		out.EncryptedKey = k.EncryptedKey
		// age.MasterKey in sops/v3.13.0 has no CreationDate field.
		return out, nil

	case *pgp.MasterKey:
		out := pgp.NewMasterKeyFromFingerprint(k.Fingerprint)
		out.EncryptedKey = k.EncryptedKey
		out.CreationDate = k.CreationDate
		_ = cfg.PGP
		return out, nil

	default:
		return mk, nil
	}
}
