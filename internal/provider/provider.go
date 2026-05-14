package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

type sopsProvider struct {
	version string
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &sopsProvider{version: version}
	}
}

func (p *sopsProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "sops"
	resp.Version = p.version
}

func (p *sopsProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "SOPS decrypt provider with first-class credential configuration.",
		Attributes: map[string]schema.Attribute{
			"concurrency_limit": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of parallel decrypt calls (default 4).",
			},
		},
		Blocks: map[string]schema.Block{
			"aws":   auth.AWSBlockSchema(),
			"gcp":   auth.GCPBlockSchema(),
			"azure": auth.AzureBlockSchema(),
			"age":   auth.AgeBlockSchema(),
			"pgp":   auth.PGPBlockSchema(),
		},
	}
}

// ProviderData is the value handed to every data source / ephemeral via req.ProviderData.
type ProviderData struct {
	Config auth.Config
}

// ProviderAuthConfig is the accessor downstream packages depend on without
// importing this package's concrete type (avoids cycles).
func (p *ProviderData) ProviderAuthConfig() auth.Config { return p.Config }

func (p *sopsProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var m ProviderModel
	diags := req.Config.Get(ctx, &m)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	cfg := auth.Config{}
	if c, d := m.AWS.ToConfig(ctx); !appendDiagsHasErr(&resp.Diagnostics, d) {
		cfg.AWS = c
	}
	if c, d := m.GCP.ToConfig(ctx); !appendDiagsHasErr(&resp.Diagnostics, d) {
		cfg.GCP = c
	}
	if c, d := m.Azure.ToConfig(ctx); !appendDiagsHasErr(&resp.Diagnostics, d) {
		cfg.Azure = c
	}
	if c, d := m.Age.ToConfig(ctx); !appendDiagsHasErr(&resp.Diagnostics, d) {
		cfg.Age = c
	}
	if c, d := m.PGP.ToConfig(ctx); !appendDiagsHasErr(&resp.Diagnostics, d) {
		cfg.PGP = c
	}
	if !m.ConcurrencyLimit.IsNull() {
		cfg.ConcurrencyLimit = int(m.ConcurrencyLimit.ValueInt64())
		sopswrap.SetGlobalConcurrency(cfg.ConcurrencyLimit)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	pd := &ProviderData{Config: cfg}
	resp.DataSourceData = pd
	resp.EphemeralResourceData = pd
}

func appendDiagsHasErr(out *diag.Diagnostics, in diag.Diagnostics) bool {
	out.Append(in...)
	return in.HasError()
}

func (p *sopsProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}
func (p *sopsProvider) EphemeralResources(_ context.Context) []func() ephemeral.EphemeralResource {
	return nil
}
func (p *sopsProvider) Resources(_ context.Context) []func() resource.Resource {
	return nil
}
func (p *sopsProvider) Functions(_ context.Context) []func() function.Function {
	return nil
}
