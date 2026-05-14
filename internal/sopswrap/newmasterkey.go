package sopswrap

import (
	"fmt"

	sops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/azkv"
	"github.com/getsops/sops/v3/gcpkms"
	"github.com/getsops/sops/v3/kms"
	"github.com/getsops/sops/v3/pgp"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

// BuildMasterKeysFromRules constructs a single KeyGroup containing one MasterKey
// per recipient in the rules. Credentials from cfg are injected into KMS keys
// (the AWS_PROFILE fix); other key types get their config via scoped env vars
// at Encrypt() call time.
//
// All recipients land in one group on purpose: SOPS' threshold semantics
// operate within a group, and a typical sops file lists "any one of these
// recipients can decrypt" — that's the single-group case. Multi-group
// (M-of-N) is out of scope for Phase 2.
func BuildMasterKeysFromRules(rules auth.CreationRules, cfg auth.Config) ([]sops.KeyGroup, error) {
	if !rules.HasAnyKey() {
		return nil, fmt.Errorf("sopswrap: creation_rules has no recipients")
	}
	group := make(sops.KeyGroup, 0, 8)

	for _, arn := range rules.KMSARNs {
		role := ""
		if cfg.AWS.AssumeRole != nil {
			role = cfg.AWS.AssumeRole.RoleARN
		}
		k := kms.NewMasterKeyWithProfile(arn, role, nil, cfg.AWS.Profile)
		group = append(group, k)
	}

	for _, resID := range rules.GCPKMSResources {
		group = append(group, gcpkms.NewMasterKeyFromResourceID(resID))
	}

	for _, url := range rules.AzureKVKeys {
		// azkv.NewMasterKeyFromURL accepts the full Azure Key Vault URL in the
		// format: https://<vault>.vault.azure.net/keys/<name>/<version>
		k, err := azkv.NewMasterKeyFromURL(url)
		if err != nil {
			return nil, fmt.Errorf("azkv parse %q: %w", url, err)
		}
		group = append(group, k)
	}

	for _, recipient := range rules.AgeRecipients {
		k, err := age.MasterKeyFromRecipient(recipient)
		if err != nil {
			return nil, fmt.Errorf("age recipient %q: %w", recipient, err)
		}
		group = append(group, k)
	}

	for _, fp := range rules.PGPFingerprints {
		group = append(group, pgp.NewMasterKeyFromFingerprint(fp))
	}

	return []sops.KeyGroup{group}, nil
}
