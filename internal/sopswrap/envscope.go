package sopswrap

import (
	"os"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

// applyScopedEnv sets SOPS-relevant env vars from cfg and returns a func that
// restores the previous values. Critical: AWS_PROFILE is intentionally NOT
// touched — the AWS profile flows through kms.MasterKey.AwsProfile (see
// RebuildKeyGroups), avoiding process-env pollution.
func applyScopedEnv(cfg auth.Config) func() {
	type restore struct {
		key string
		val string
		ok  bool
	}
	var saves []restore

	set := func(k, v string) {
		if v == "" {
			return
		}
		old, ok := os.LookupEnv(k)
		saves = append(saves, restore{k, old, ok})
		_ = os.Setenv(k, v)
	}

	set("SOPS_AGE_KEY", cfg.Age.Key)
	set("SOPS_AGE_KEY_FILE", cfg.Age.KeyFile)
	set("SOPS_AGE_KEY_CMD", cfg.Age.KeyCommand)
	set("SOPS_AGE_SSH_PRIVATE_KEY_FILE", cfg.Age.SSHPrivateKeyFile)
	set("GOOGLE_APPLICATION_CREDENTIALS", cfg.GCP.CredentialsFile)
	set("GNUPGHOME", cfg.PGP.GnupgHome)

	return func() {
		for _, r := range saves {
			if r.ok {
				_ = os.Setenv(r.key, r.val)
			} else {
				_ = os.Unsetenv(r.key)
			}
		}
	}
}
