package ephemeral

import (
	"context"
	"fmt"
	"os"

	fwephemeral "github.com/hashicorp/terraform-plugin-framework/ephemeral"
	epschema "github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

// fileEphemeral implements ephemeral "sops_file".
// Plaintext is never serialised to plan or state.
type fileEphemeral struct {
	providerCfg auth.Config
}

// NewFileEphemeral returns a new fileEphemeral factory function.
func NewFileEphemeral() fwephemeral.EphemeralResource {
	return &fileEphemeral{}
}

// Ensure fileEphemeral implements optional Configure interface.
var _ fwephemeral.EphemeralResourceWithConfigure = (*fileEphemeral)(nil)

func (e *fileEphemeral) Metadata(_ context.Context, req fwephemeral.MetadataRequest, resp *fwephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_file"
}

func (e *fileEphemeral) Configure(_ context.Context, req fwephemeral.ConfigureRequest, _ *fwephemeral.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	acc, ok := req.ProviderData.(ProviderDataAccessor)
	if !ok {
		return
	}
	e.providerCfg = acc.ProviderAuthConfig()
}

func (e *fileEphemeral) Schema(_ context.Context, _ fwephemeral.SchemaRequest, resp *fwephemeral.SchemaResponse) {
	resp.Schema = epschema.Schema{
		Description: "Decrypts a SOPS-encrypted file from disk. Plaintext never reaches plan/state.",
		Attributes: map[string]epschema.Attribute{
			"source_file": epschema.StringAttribute{Required: true, Description: "Path to the SOPS-encrypted file."},
			"input_type":  epschema.StringAttribute{Optional: true, Description: "yaml, json, dotenv, ini, binary, or raw. Auto-detected from extension when omitted."},
			"data":        epschema.MapAttribute{Computed: true, ElementType: types.StringType, Sensitive: true, Description: "Flat map (carlpett-compatible)."},
			"data_json":   epschema.StringAttribute{Computed: true, Sensitive: true, Description: "Structured nested JSON of the decrypted tree."},
			"raw":         epschema.StringAttribute{Computed: true, Sensitive: true, Description: "Decrypted bytes as a string."},
			"metadata":    metadataAttribute(),
		},
		Blocks: map[string]epschema.Block{
			"aws":   auth.AWSBlockSchemaForEphemeral(),
			"gcp":   auth.GCPBlockSchemaForEphemeral(),
			"azure": auth.AzureBlockSchemaForEphemeral(),
			"age":   auth.AgeBlockSchemaForEphemeral(),
			"pgp":   auth.PGPBlockSchemaForEphemeral(),
		},
	}
}

type fileEphemeralModel struct {
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

func (e *fileEphemeral) Open(ctx context.Context, req fwephemeral.OpenRequest, resp *fwephemeral.OpenResponse) {
	var m fileEphemeralModel
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

	perCall := buildPerCallConfigEphemeral(ctx, m.AWS, m.GCP, m.Azure, m.Age, m.PGP, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	cfg := auth.Merge(e.providerCfg, perCall)

	out, err := sopswrap.Decrypt(ctx, sopswrap.DecryptInput{
		Source: src, Format: format, Config: cfg,
	})
	if err != nil {
		resp.Diagnostics.AddError("sops decrypt failed",
			fmt.Sprintf("path=%q: %s\n\nIf this is an auth failure, check that your `aws {}` / `gcp {}` / `age {}` block on the provider or ephemeral resource matches the key principals on the file.", path, err))
		return
	}

	m.Raw = types.StringValue(string(out.Plaintext))
	m.DataJSON = types.StringValue(string(out.JSON))
	m.Data, _ = types.MapValueFrom(ctx, types.StringType, out.Flat)
	m.Metadata = metadataObjectValue(ctx, out.Metadata)

	resp.Diagnostics.Append(resp.Result.Set(ctx, &m)...)
}
