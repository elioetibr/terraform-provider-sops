// Package auth defines the credential configuration types shared by the
// provider block, per-resource overrides, and the sopswrap layer.
package auth

import "time"

// Config is the merged credential configuration for a single decrypt or encrypt call.
// Construct via auth.Merge(providerConfig, perCallConfig).
type Config struct {
	AWS   AWSConfig
	GCP   GCPConfig
	Azure AzureConfig
	Age   AgeConfig
	PGP   PGPConfig

	// ConcurrencyLimit caps parallel decrypts. Zero means "use package default".
	ConcurrencyLimit int
}

// AWSConfig holds AWS-specific credential configuration.
type AWSConfig struct {
	Profile                string
	Region                 string
	SharedConfigFiles      []string
	SharedCredentialsFiles []string
	Env                    map[string]string
	AssumeRole             *AWSAssumeRole
}

// AWSAssumeRole holds configuration for assuming an AWS IAM role.
type AWSAssumeRole struct {
	RoleARN     string
	SessionName string
	ExternalID  string
	Duration    time.Duration
}

// GCPConfig holds GCP-specific credential configuration.
type GCPConfig struct {
	Credentials               string // raw JSON
	CredentialsFile           string
	ImpersonateServiceAccount string
	QuotaProject              string
}

// AzureConfig holds Azure-specific credential configuration.
type AzureConfig struct {
	TenantID            string
	ClientID            string
	ClientSecret        string
	UseMSI              bool
	UseOIDC             bool
	UseWorkloadIdentity bool
	UseCLI              bool
}

// AgeConfig holds age encryption key configuration.
type AgeConfig struct {
	Key               string // explicit private key material
	KeyFile           string
	KeyCommand        string
	SSHPrivateKeyFile string
}

// PGPConfig holds PGP/GPG credential configuration.
type PGPConfig struct {
	GnupgHome string
}
