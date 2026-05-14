// Package datasources implements the read-side Terraform data sources.
package datasources

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

// ProviderDataAccessor is what the provider hands us via DataSourceData.
type ProviderDataAccessor interface {
	ProviderAuthConfig() auth.Config
}

// fileDataSource implements data "sops_file".
type fileDataSource struct {
	providerCfg auth.Config
}

// NewFileDataSource returns a new fileDataSource factory function.
func NewFileDataSource() datasource.DataSource {
	return &fileDataSource{}
}

func (d *fileDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_file"
}

func (d *fileDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	acc, ok := req.ProviderData.(ProviderDataAccessor)
	if !ok {
		return
	}
	d.providerCfg = acc.ProviderAuthConfig()
}

func (d *fileDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Decrypts a SOPS-encrypted file from disk.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Computed: true},
			"source_file": schema.StringAttribute{Required: true, Description: "Path to the SOPS-encrypted file."},
			"input_type":  schema.StringAttribute{Optional: true, Description: "yaml, json, dotenv, ini, binary, or raw. Auto-detected from extension when omitted."},
			"data":        schema.MapAttribute{Computed: true, ElementType: types.StringType, Sensitive: true, Description: "Flat map (carlpett-compatible)."},
			"data_json":   schema.StringAttribute{Computed: true, Sensitive: true, Description: "Structured nested JSON of the decrypted tree."},
			"raw":         schema.StringAttribute{Computed: true, Sensitive: true, Description: "Decrypted bytes as a string."},
			"metadata":    metadataAttribute(),
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

type fileModel struct {
	ID         types.String     `tfsdk:"id"`
	SourceFile types.String     `tfsdk:"source_file"`
	InputType  types.String     `tfsdk:"input_type"`
	Data       types.Map        `tfsdk:"data"`
	DataJSON   types.String     `tfsdk:"data_json"`
	Raw        types.String     `tfsdk:"raw"`
	Metadata   types.Object     `tfsdk:"metadata"`
	AWS        *auth.AWSModel   `tfsdk:"aws"`
	GCP        *auth.GCPModel   `tfsdk:"gcp"`
	Azure      *auth.AzureModel `tfsdk:"azure"`
	Age        *auth.AgeModel   `tfsdk:"age"`
	PGP        *auth.PGPModel   `tfsdk:"pgp"`
}

func (d *fileDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m fileModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}

	path := m.SourceFile.ValueString()
	src, err := os.ReadFile(path)
	if err != nil {
		resp.Diagnostics.AddError("could not read source_file",
			fmt.Sprintf("path=%q: %s", path, err))
		return
	}

	format := sopswrap.Format(m.InputType.ValueString())
	if format == "" {
		format = sopswrap.FormatFromPath(path)
	}

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
			fmt.Sprintf("path=%q: %s\n\nIf this is an auth failure, check that your `aws {}` / `gcp {}` / `age {}` block on the provider or data source matches the key principals on the file.", path, err))
		return
	}

	m.ID = types.StringValue(path)
	m.Raw = types.StringValue(string(out.Plaintext))
	m.DataJSON = types.StringValue(string(out.JSON))
	m.Data, _ = types.MapValueFrom(ctx, types.StringType, out.Flat)
	m.Metadata = metadataObjectValue(ctx, out.Metadata)

	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
