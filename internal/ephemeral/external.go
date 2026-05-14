package ephemeral

import (
	"context"
	"fmt"

	fwephemeral "github.com/hashicorp/terraform-plugin-framework/ephemeral"
	epschema "github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

// externalEphemeral implements ephemeral "sops_external".
// Accepts ciphertext as an inline string; plaintext never reaches plan/state.
type externalEphemeral struct {
	providerCfg auth.Config
}

// NewExternalEphemeral returns a new externalEphemeral factory function.
func NewExternalEphemeral() fwephemeral.EphemeralResource {
	return &externalEphemeral{}
}

// Ensure externalEphemeral implements optional Configure interface.
var _ fwephemeral.EphemeralResourceWithConfigure = (*externalEphemeral)(nil)

func (e *externalEphemeral) Metadata(_ context.Context, req fwephemeral.MetadataRequest, resp *fwephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_external"
}

func (e *externalEphemeral) Configure(_ context.Context, req fwephemeral.ConfigureRequest, _ *fwephemeral.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	acc, ok := req.ProviderData.(ProviderDataAccessor)
	if !ok {
		return
	}
	e.providerCfg = acc.ProviderAuthConfig()
}

func (e *externalEphemeral) Schema(_ context.Context, _ fwephemeral.SchemaRequest, resp *fwephemeral.SchemaResponse) {
	resp.Schema = epschema.Schema{
		Description: "Decrypts a SOPS-encrypted ciphertext supplied as a string. Plaintext never reaches plan/state.",
		Attributes: map[string]epschema.Attribute{
			"source":     epschema.StringAttribute{Required: true, Description: "SOPS-encrypted ciphertext string.", Sensitive: true},
			"input_type": epschema.StringAttribute{Required: true, Description: "yaml, json, dotenv, ini, binary, or raw."},
			"data":       epschema.MapAttribute{Computed: true, ElementType: types.StringType, Sensitive: true, Description: "Flat map (carlpett-compatible)."},
			"data_json":  epschema.StringAttribute{Computed: true, Sensitive: true, Description: "Structured nested JSON of the decrypted tree."},
			"raw":        epschema.StringAttribute{Computed: true, Sensitive: true, Description: "Decrypted bytes as a string."},
			"metadata":   metadataAttribute(),
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

type externalEphemeralModel struct {
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

func (e *externalEphemeral) Open(ctx context.Context, req fwephemeral.OpenRequest, resp *fwephemeral.OpenResponse) {
	var m externalEphemeralModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}

	src := []byte(m.Source.ValueString())
	format := sopswrap.Format(m.InputType.ValueString())

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
			fmt.Sprintf("input_type=%q: %s\n\nIf this is an auth failure, check that your `aws {}` / `gcp {}` / `age {}` block on the provider or ephemeral resource matches the key principals on the file.", m.InputType.ValueString(), err))
		return
	}

	m.Raw = types.StringValue(string(out.Plaintext))
	m.DataJSON = types.StringValue(string(out.JSON))
	m.Data, _ = types.MapValueFrom(ctx, types.StringType, out.Flat)
	m.Metadata = metadataObjectValue(ctx, out.Metadata)

	resp.Diagnostics.Append(resp.Result.Set(ctx, &m)...)
}
