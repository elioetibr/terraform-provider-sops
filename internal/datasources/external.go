// Package datasources implements the read-side Terraform data sources.
package datasources

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

// externalDataSource implements data "sops_external".
// Unlike sops_file it accepts the ciphertext as an inline string via `source`,
// so callers do not need file-system access (useful for secrets stored in
// Terraform outputs or passed from another source).
type externalDataSource struct {
	providerCfg auth.Config
}

// NewExternalDataSource returns a new externalDataSource factory function.
func NewExternalDataSource() datasource.DataSource {
	return &externalDataSource{}
}

func (d *externalDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_external"
}

func (d *externalDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	acc, ok := req.ProviderData.(ProviderDataAccessor)
	if !ok {
		return
	}
	d.providerCfg = acc.ProviderAuthConfig()
}

func (d *externalDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Decrypts a SOPS-encrypted ciphertext supplied as a string.",
		Attributes: map[string]schema.Attribute{
			"id":         schema.StringAttribute{Computed: true},
			"source":     schema.StringAttribute{Required: true, Description: "SOPS-encrypted ciphertext string.", Sensitive: true},
			"input_type": schema.StringAttribute{Required: true, Description: "yaml, json, dotenv, ini, binary, or raw."},
			"data":       schema.MapAttribute{Computed: true, ElementType: types.StringType, Sensitive: true, Description: "Flat map (carlpett-compatible)."},
			"data_json":  schema.StringAttribute{Computed: true, Sensitive: true, Description: "Structured nested JSON of the decrypted tree."},
			"raw":        schema.StringAttribute{Computed: true, Sensitive: true, Description: "Decrypted bytes as a string."},
			"metadata":   metadataAttribute(),
		},
		Blocks: map[string]schema.Block{
			"aws":   auth.AWSBlockSchemaForDataSource(),
			"gcp":   auth.GCPBlockSchemaForDataSource(),
			"azure": auth.AzureBlockSchemaForDataSource(),
			"age":   auth.AgeBlockSchemaForDataSource(),
			"pgp":   auth.PGPBlockSchemaForDataSource(),
		},
	}
}

type externalModel struct {
	ID        types.String     `tfsdk:"id"`
	Source    types.String     `tfsdk:"source"`
	InputType types.String     `tfsdk:"input_type"`
	Data      types.Map        `tfsdk:"data"`
	DataJSON  types.String     `tfsdk:"data_json"`
	Raw       types.String     `tfsdk:"raw"`
	Metadata  types.Object     `tfsdk:"metadata"`
	AWS       *auth.AWSModel   `tfsdk:"aws"`
	GCP       *auth.GCPModel   `tfsdk:"gcp"`
	Azure     *auth.AzureModel `tfsdk:"azure"`
	Age       *auth.AgeModel   `tfsdk:"age"`
	PGP       *auth.PGPModel   `tfsdk:"pgp"`
}

func (d *externalDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m externalModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}

	src := []byte(m.Source.ValueString())
	format := sopswrap.Format(m.InputType.ValueString())

	perCall := buildPerCallConfig(ctx, m.AWS, m.GCP, m.Azure, m.Age, m.PGP, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	cfg := auth.Merge(d.providerCfg, perCall)

	out, err := sopswrap.Decrypt(ctx, sopswrap.DecryptInput{
		Source: src, Format: format, Config: cfg,
	})
	if err != nil {
		resp.Diagnostics.AddError("sops decrypt failed",
			fmt.Sprintf("input_type=%q: %s\n\nIf this is an auth failure, check that your `aws {}` / `gcp {}` / `age {}` block on the provider or data source matches the key principals on the file.", m.InputType.ValueString(), err))
		return
	}

	// Use a stable hash of the source as the computed ID.
	m.ID = types.StringValue(fmt.Sprintf("sops_external:%d", len(src)))
	m.Raw = types.StringValue(string(out.Plaintext))
	m.DataJSON = types.StringValue(string(out.JSON))
	m.Data, _ = types.MapValueFrom(ctx, types.StringType, out.Flat)
	m.Metadata = metadataObjectValue(ctx, out.Metadata)

	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
