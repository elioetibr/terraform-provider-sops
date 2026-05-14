package auth

// Merge overlays perCall onto provider, returning a new Config.
//
// Semantics (per spec §5.3):
//   - Leaf strings/ints/durations: perCall wins iff non-zero.
//   - Bools: perCall wins iff true (no way to express "explicit false override"
//     at the schema level for now; users wanting to disable a provider-level
//     bool should omit the provider-level block on that resource via alias).
//   - Slices: perCall wins atomically iff non-nil and non-empty.
//   - Pointer structs (AssumeRole): perCall wins atomically iff non-nil.
//   - Maps (AWSConfig.Env): perCall keys overlay provider keys.
func Merge(provider, perCall Config) Config {
	out := provider
	out.AWS = mergeAWS(provider.AWS, perCall.AWS)
	out.GCP = mergeGCP(provider.GCP, perCall.GCP)
	out.Azure = mergeAzure(provider.Azure, perCall.Azure)
	out.Age = mergeAge(provider.Age, perCall.Age)
	out.PGP = mergePGP(provider.PGP, perCall.PGP)
	if perCall.ConcurrencyLimit != 0 {
		out.ConcurrencyLimit = perCall.ConcurrencyLimit
	}
	return out
}

func mergeAWS(p, c AWSConfig) AWSConfig {
	out := p
	if c.Profile != "" {
		out.Profile = c.Profile
	}
	if c.Region != "" {
		out.Region = c.Region
	}
	if len(c.SharedConfigFiles) > 0 {
		out.SharedConfigFiles = c.SharedConfigFiles
	}
	if len(c.SharedCredentialsFiles) > 0 {
		out.SharedCredentialsFiles = c.SharedCredentialsFiles
	}
	if len(c.Env) > 0 {
		if out.Env == nil {
			out.Env = map[string]string{}
		} else {
			merged := make(map[string]string, len(out.Env)+len(c.Env))
			for k, v := range out.Env {
				merged[k] = v
			}
			out.Env = merged
		}
		for k, v := range c.Env {
			out.Env[k] = v
		}
	}
	if c.AssumeRole != nil {
		ar := *c.AssumeRole
		out.AssumeRole = &ar
	}
	return out
}

func mergeGCP(p, c GCPConfig) GCPConfig {
	out := p
	if c.Credentials != "" {
		out.Credentials = c.Credentials
	}
	if c.CredentialsFile != "" {
		out.CredentialsFile = c.CredentialsFile
	}
	if c.ImpersonateServiceAccount != "" {
		out.ImpersonateServiceAccount = c.ImpersonateServiceAccount
	}
	if c.QuotaProject != "" {
		out.QuotaProject = c.QuotaProject
	}
	return out
}

func mergeAzure(p, c AzureConfig) AzureConfig {
	out := p
	if c.TenantID != "" {
		out.TenantID = c.TenantID
	}
	if c.ClientID != "" {
		out.ClientID = c.ClientID
	}
	if c.ClientSecret != "" {
		out.ClientSecret = c.ClientSecret
	}
	if c.UseMSI {
		out.UseMSI = true
	}
	if c.UseOIDC {
		out.UseOIDC = true
	}
	if c.UseWorkloadIdentity {
		out.UseWorkloadIdentity = true
	}
	if c.UseCLI {
		out.UseCLI = true
	}
	return out
}

func mergeAge(p, c AgeConfig) AgeConfig {
	out := p
	if c.Key != "" {
		out.Key = c.Key
	}
	if c.KeyFile != "" {
		out.KeyFile = c.KeyFile
	}
	if c.KeyCommand != "" {
		out.KeyCommand = c.KeyCommand
	}
	if c.SSHPrivateKeyFile != "" {
		out.SSHPrivateKeyFile = c.SSHPrivateKeyFile
	}
	return out
}

func mergePGP(p, c PGPConfig) PGPConfig {
	out := p
	if c.GnupgHome != "" {
		out.GnupgHome = c.GnupgHome
	}
	return out
}
