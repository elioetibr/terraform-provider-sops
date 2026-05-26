package resources

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	fwpath "github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

// ProviderDataAccessor is the interface the provider hands us via ProviderData.
type ProviderDataAccessor interface {
	ProviderAuthConfig() auth.Config
}

// fileResource implements resource "sops_file".
type fileResource struct {
	providerCfg auth.Config
}

// NewFileResource returns a factory function for the sops_file managed resource.
func NewFileResource() resource.Resource {
	return &fileResource{}
}

// Ensure fileResource implements the framework interfaces it needs.
var (
	_ resource.ResourceWithConfigure  = (*fileResource)(nil)
	_ resource.ResourceWithModifyPlan = (*fileResource)(nil)
)

// fileModel is the tfsdk state/plan model for sops_file.
type fileModel struct {
	ID               types.String             `tfsdk:"id"`
	Path             types.String             `tfsdk:"path"`
	ContentWO        types.String             `tfsdk:"content_wo"`
	ContentWOVersion types.String             `tfsdk:"content_wo_version"`
	InputType        types.String             `tfsdk:"input_type"`
	RotateKeys       types.Bool               `tfsdk:"rotate_keys"`
	PlaintextSHA256  types.String             `tfsdk:"plaintext_sha256"`
	SopsMAC          types.String             `tfsdk:"sops_mac"`
	SopsLastModified types.String             `tfsdk:"sops_last_modified"`
	Metadata         types.Object             `tfsdk:"metadata"`
	AWS              *auth.AWSModel           `tfsdk:"aws"`
	GCP              *auth.GCPModel           `tfsdk:"gcp"`
	Azure            *auth.AzureModel         `tfsdk:"azure"`
	Age              *auth.AgeModel           `tfsdk:"age"`
	PGP              *auth.PGPModel           `tfsdk:"pgp"`
	CreationRules    *auth.CreationRulesModel `tfsdk:"creation_rules"`
}

func (r *fileResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_file"
}

func (r *fileResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	if acc, ok := req.ProviderData.(ProviderDataAccessor); ok {
		r.providerCfg = acc.ProviderAuthConfig()
	}
}

func (r *fileResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = rschema.Schema{
		Description: "Encrypts plaintext content to a SOPS-encrypted file on disk.",
		Attributes: map[string]rschema.Attribute{
			"id": rschema.StringAttribute{
				Computed:    true,
				Description: "Same as path. Used as the resource identity.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"path": rschema.StringAttribute{
				Required:    true,
				Description: "Destination path for the encrypted file.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"content_wo": rschema.StringAttribute{
				Required:    true,
				WriteOnly:   true,
				Sensitive:   true,
				Description: "Plaintext content to encrypt. Write-only — never stored in state. Bump content_wo_version to trigger re-encryption.",
			},
			"content_wo_version": rschema.StringAttribute{
				Required:    true,
				Description: "Version token for content_wo. Changing this value triggers re-encryption of the file.",
			},
			"input_type": rschema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "yaml, json, dotenv, ini, binary, or raw. Auto-detected from path extension when omitted.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"rotate_keys": rschema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "When true on Update, rotate master keys without re-encrypting plaintext.",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"plaintext_sha256": rschema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "SHA-256 of the decrypted plaintext. Used for out-of-band drift detection.",
			},
			"sops_mac": rschema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "SOPS message authentication code from the encrypted file.",
			},
			"sops_last_modified": rschema.StringAttribute{
				Computed:    true,
				Description: "RFC3339 timestamp of the last SOPS encryption.",
			},
			"metadata": metadataSchemaAttribute(),
		},
		Blocks: map[string]rschema.Block{
			"aws":            auth.AWSBlockSchemaForResource(),
			"gcp":            auth.GCPBlockSchemaForResource(),
			"azure":          auth.AzureBlockSchemaForResource(),
			"age":            auth.AgeBlockSchemaForResource(),
			"pgp":            auth.PGPBlockSchemaForResource(),
			"creation_rules": auth.CreationRulesResourceBlockSchema(),
		},
	}
}

// Create implements resource.Resource.
func (r *fileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan fileModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Write-only attribute: must be read from Config, not Plan (framework does not populate it in Plan).
	var contentWO types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, fwpath.Root("content_wo"), &contentWO)...)
	if resp.Diagnostics.HasError() {
		return
	}

	perCall := buildPerCallConfig(ctx, plan.AWS, plan.GCP, plan.Azure, plan.Age, plan.PGP, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	cfg := auth.Merge(r.providerCfg, perCall)

	if plan.CreationRules == nil {
		resp.Diagnostics.AddError(
			"creation_rules required",
			"The creation_rules block must be set on sops_file to specify encryption keys.",
		)
		return
	}
	rules, d := plan.CreationRules.ToConfig(ctx)
	if appendDiagsHasErr(&resp.Diagnostics, d) {
		return
	}

	destPath := plan.Path.ValueString()
	format := resolveFormat(plan.InputType.ValueString(), destPath)

	result, err := sopswrap.Encrypt(ctx, sopswrap.EncryptInput{
		Plaintext: []byte(contentWO.ValueString()),
		Format:    format,
		Rules:     rules,
		Config:    cfg,
	})
	if err != nil {
		resp.Diagnostics.AddError("sops encrypt failed",
			fmt.Sprintf("path=%q: %s", destPath, err))
		return
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		resp.Diagnostics.AddError("could not create parent directory",
			fmt.Sprintf("path=%q: %s", destPath, err))
		return
	}
	if err := os.WriteFile(destPath, result.Ciphertext, 0o600); err != nil {
		resp.Diagnostics.AddError("could not write encrypted file",
			fmt.Sprintf("path=%q: %s", destPath, err))
		return
	}

	plan.ID = types.StringValue(destPath)
	plan.InputType = types.StringValue(string(format))
	plan.PlaintextSHA256 = types.StringValue(PlaintextDigest(result.CanonicalPlaintext))
	plan.SopsMAC = types.StringValue(result.Metadata.MAC)
	plan.SopsLastModified = types.StringValue(result.Metadata.LastModified.Format(time.RFC3339))
	plan.Metadata = metadataObjectValue(ctx, result.Metadata)
	if plan.RotateKeys.IsNull() || plan.RotateKeys.IsUnknown() {
		plan.RotateKeys = types.BoolValue(false)
	}
	// Never store the write-only value in state.
	plan.ContentWO = types.StringNull()

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read implements resource.Resource (drift detection).
func (r *fileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state fileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	destPath := state.Path.ValueString()
	ciphertext, err := os.ReadFile(destPath)
	if err != nil {
		if os.IsNotExist(err) {
			// File deleted out-of-band — signal Terraform to re-create it.
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("could not read encrypted file",
			fmt.Sprintf("path=%q: %s", destPath, err))
		return
	}

	format := resolveFormat(state.InputType.ValueString(), destPath)

	perCall := buildPerCallConfig(ctx, state.AWS, state.GCP, state.Azure, state.Age, state.PGP, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	cfg := auth.Merge(r.providerCfg, perCall)

	out, err := sopswrap.Decrypt(ctx, sopswrap.DecryptInput{
		Source: ciphertext, Format: format, Config: cfg,
	})
	if err != nil {
		resp.Diagnostics.AddError("sops decrypt failed during drift check",
			fmt.Sprintf("path=%q: %s", destPath, err))
		return
	}

	// Audit fields refresh from the on-disk file. plaintext_sha256 deliberately
	// is NOT updated here — it's a commitment fingerprint set at Create/Update
	// time; ModifyPlan compares it against the file's current decrypted digest
	// to surface drift. Updating it here would silently absorb the drift.
	state.SopsMAC = types.StringValue(out.Metadata.MAC)
	state.SopsLastModified = types.StringValue(out.Metadata.LastModified.Format(time.RFC3339))
	state.Metadata = metadataObjectValue(ctx, out.Metadata)
	// Write-only attribute must always be null in state.
	state.ContentWO = types.StringNull()

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update implements resource.Resource.
func (r *fileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan fileModel
	var state fileModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	destPath := plan.Path.ValueString()
	format := resolveFormat(plan.InputType.ValueString(), destPath)

	perCall := buildPerCallConfig(ctx, plan.AWS, plan.GCP, plan.Azure, plan.Age, plan.PGP, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	cfg := auth.Merge(r.providerCfg, perCall)

	rotateKeys := plan.RotateKeys.ValueBool()
	versionChanged := !plan.ContentWOVersion.Equal(state.ContentWOVersion)

	switch {
	case rotateKeys && !versionChanged:
		// Key rotation only — do NOT re-encrypt plaintext.
		if err := r.doKeyRotation(ctx, plan, state, destPath, format, cfg, resp); err != nil {
			return
		}

	case versionChanged:
		// Re-encrypt with new plaintext.
		if err := r.doReEncrypt(ctx, req, plan, destPath, format, cfg, resp); err != nil {
			return
		}

	default:
		// Nothing changed — propagate existing computed values.
		plan.ID = state.ID
		plan.InputType = state.InputType
		plan.PlaintextSHA256 = state.PlaintextSHA256
		plan.SopsMAC = state.SopsMAC
		plan.SopsLastModified = state.SopsLastModified
		plan.Metadata = state.Metadata
		plan.ContentWO = types.StringNull()
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

// doKeyRotation rotates master keys on the existing encrypted file.
func (r *fileResource) doKeyRotation(
	ctx context.Context,
	plan fileModel,
	state fileModel,
	destPath string,
	format sopswrap.Format,
	cfg auth.Config,
	resp *resource.UpdateResponse,
) error {
	if plan.CreationRules == nil {
		resp.Diagnostics.AddError(
			"creation_rules required for key rotation",
			"The creation_rules block must be set when rotate_keys = true.",
		)
		return fmt.Errorf("creation_rules missing")
	}
	newRules, d := plan.CreationRules.ToConfig(ctx)
	if appendDiagsHasErr(&resp.Diagnostics, d) {
		return fmt.Errorf("creation_rules error")
	}

	existing, err := os.ReadFile(destPath)
	if err != nil {
		resp.Diagnostics.AddError("could not read file for key rotation",
			fmt.Sprintf("path=%q: %s", destPath, err))
		return err
	}

	result, err := sopswrap.UpdateKeys(ctx, sopswrap.UpdateKeysInput{
		Source:   existing,
		Format:   format,
		NewRules: newRules,
		Config:   cfg,
	})
	if err != nil {
		resp.Diagnostics.AddError("sops key rotation failed",
			fmt.Sprintf("path=%q: %s", destPath, err))
		return err
	}

	if err := os.WriteFile(destPath, result.Ciphertext, 0o600); err != nil {
		resp.Diagnostics.AddError("could not write rotated file",
			fmt.Sprintf("path=%q: %s", destPath, err))
		return err
	}

	plan.ID = types.StringValue(destPath)
	plan.InputType = types.StringValue(string(format))
	// Preserve plaintext digest — rotation never changes the plaintext.
	plan.PlaintextSHA256 = state.PlaintextSHA256
	plan.SopsMAC = types.StringValue(result.Metadata.MAC)
	plan.SopsLastModified = types.StringValue(result.Metadata.LastModified.Format(time.RFC3339))
	plan.Metadata = metadataObjectValue(ctx, result.Metadata)
	plan.ContentWO = types.StringNull()

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	return nil
}

// doReEncrypt re-encrypts the file with new plaintext from content_wo.
func (r *fileResource) doReEncrypt(
	ctx context.Context,
	req resource.UpdateRequest,
	plan fileModel,
	destPath string,
	format sopswrap.Format,
	cfg auth.Config,
	resp *resource.UpdateResponse,
) error {
	var contentWO types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, fwpath.Root("content_wo"), &contentWO)...)
	if resp.Diagnostics.HasError() {
		return fmt.Errorf("content_wo read error")
	}

	if plan.CreationRules == nil {
		resp.Diagnostics.AddError(
			"creation_rules required",
			"The creation_rules block must be set on sops_file to specify encryption keys.",
		)
		return fmt.Errorf("creation_rules missing")
	}
	rules, d := plan.CreationRules.ToConfig(ctx)
	if appendDiagsHasErr(&resp.Diagnostics, d) {
		return fmt.Errorf("creation_rules error")
	}

	result, err := sopswrap.Encrypt(ctx, sopswrap.EncryptInput{
		Plaintext: []byte(contentWO.ValueString()),
		Format:    format,
		Rules:     rules,
		Config:    cfg,
	})
	if err != nil {
		resp.Diagnostics.AddError("sops encrypt failed",
			fmt.Sprintf("path=%q: %s", destPath, err))
		return err
	}

	if err := os.WriteFile(destPath, result.Ciphertext, 0o600); err != nil {
		resp.Diagnostics.AddError("could not write re-encrypted file",
			fmt.Sprintf("path=%q: %s", destPath, err))
		return err
	}

	plan.ID = types.StringValue(destPath)
	plan.InputType = types.StringValue(string(format))
	plan.PlaintextSHA256 = types.StringValue(PlaintextDigest(result.CanonicalPlaintext))
	plan.SopsMAC = types.StringValue(result.Metadata.MAC)
	plan.SopsLastModified = types.StringValue(result.Metadata.LastModified.Format(time.RFC3339))
	plan.Metadata = metadataObjectValue(ctx, result.Metadata)
	plan.ContentWO = types.StringNull()

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	return nil
}

// ModifyPlan surfaces out-of-band drift. When the file on disk decrypts to a
// plaintext whose SHA-256 differs from state.plaintext_sha256, computed
// attributes are marked unknown so the plan shows a diff. Drift only
// auto-remediates when the user bumps content_wo_version or sets
// rotate_keys = true; otherwise the diff persists, signalling tamper.
func (r *fileResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return // create or destroy
	}

	var state, plan fileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	destPath := state.Path.ValueString()
	ciphertext, err := os.ReadFile(destPath)
	if err != nil {
		return // Read will handle missing file
	}

	format := resolveFormat(state.InputType.ValueString(), destPath)
	perCall := buildPerCallConfig(ctx, plan.AWS, plan.GCP, plan.Azure, plan.Age, plan.PGP, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	cfg := auth.Merge(r.providerCfg, perCall)

	out, err := sopswrap.Decrypt(ctx, sopswrap.DecryptInput{
		Source: ciphertext, Format: format, Config: cfg,
	})
	if err != nil {
		return // can't decrypt — leave plan alone, Read will surface the error
	}

	if state.PlaintextSHA256.ValueString() == PlaintextDigest(out.Plaintext) {
		return // no drift
	}

	plan.PlaintextSHA256 = types.StringUnknown()
	plan.SopsMAC = types.StringUnknown()
	plan.SopsLastModified = types.StringUnknown()
	plan.Metadata = types.ObjectUnknown(metadataAttrTypes())
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

// Delete implements resource.Resource.
func (r *fileResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state fileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	destPath := state.Path.ValueString()
	if err := os.Remove(destPath); err != nil && !os.IsNotExist(err) {
		resp.Diagnostics.AddError("could not delete encrypted file",
			fmt.Sprintf("path=%q: %s", destPath, err))
	}
}

// resolveFormat returns the sopswrap.Format, auto-detecting from path if inputType is empty.
func resolveFormat(inputType, path string) sopswrap.Format {
	if inputType != "" {
		return sopswrap.Format(inputType)
	}
	return sopswrap.FormatFromPath(path)
}

// metadataSchemaAttribute returns the computed metadata nested attribute for the resource schema.
func metadataSchemaAttribute() rschema.Attribute {
	return rschema.SingleNestedAttribute{
		Computed: true,
		Attributes: map[string]rschema.Attribute{
			"lastmodified":      rschema.StringAttribute{Computed: true},
			"mac":               rschema.StringAttribute{Computed: true, Sensitive: true},
			"version":           rschema.StringAttribute{Computed: true},
			"kms_arns":          rschema.ListAttribute{Computed: true, ElementType: types.StringType},
			"gcp_kms_resources": rschema.ListAttribute{Computed: true, ElementType: types.StringType},
			"azure_kv_urls":     rschema.ListAttribute{Computed: true, ElementType: types.StringType},
			"age_recipients":    rschema.ListAttribute{Computed: true, ElementType: types.StringType},
			"pgp_fingerprints":  rschema.ListAttribute{Computed: true, ElementType: types.StringType},
		},
	}
}

// metadataAttrTypes returns the attr.Type map matching metadataSchemaAttribute.
func metadataAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"lastmodified":      types.StringType,
		"mac":               types.StringType,
		"version":           types.StringType,
		"kms_arns":          types.ListType{ElemType: types.StringType},
		"gcp_kms_resources": types.ListType{ElemType: types.StringType},
		"azure_kv_urls":     types.ListType{ElemType: types.StringType},
		"age_recipients":    types.ListType{ElemType: types.StringType},
		"pgp_fingerprints":  types.ListType{ElemType: types.StringType},
	}
}

// metadataObjectValue converts a sopswrap.Metadata into a types.Object.
func metadataObjectValue(ctx context.Context, md sopswrap.Metadata) types.Object {
	attrs := map[string]attr.Value{
		"lastmodified":      types.StringValue(md.LastModified.Format(time.RFC3339)),
		"mac":               types.StringValue(md.MAC),
		"version":           types.StringValue(md.Version),
		"kms_arns":          listOfStrings(ctx, md.KMSARNs),
		"gcp_kms_resources": listOfStrings(ctx, md.GCPKMSResources),
		"azure_kv_urls":     listOfStrings(ctx, md.AzureKVURLs),
		"age_recipients":    listOfStrings(ctx, md.AgeRecipients),
		"pgp_fingerprints":  listOfStrings(ctx, md.PGPFingerprints),
	}
	obj, _ := types.ObjectValue(metadataAttrTypes(), attrs)
	return obj
}

// listOfStrings builds a types.List from a []string.
func listOfStrings(ctx context.Context, ss []string) types.List {
	if len(ss) == 0 {
		l, _ := types.ListValue(types.StringType, []attr.Value{})
		return l
	}
	vals := make([]attr.Value, len(ss))
	for i, s := range ss {
		vals[i] = types.StringValue(s)
	}
	l, _ := types.ListValue(types.StringType, vals)
	return l
}

// buildPerCallConfig assembles a per-call auth.Config from the optional per-resource auth blocks.
func buildPerCallConfig(
	ctx context.Context,
	aws *auth.AWSModel,
	gcp *auth.GCPModel,
	azure *auth.AzureModel,
	age *auth.AgeModel,
	pgp *auth.PGPModel,
	diags *fwDiags,
) auth.Config {
	var cfg auth.Config
	if c, d := aws.ToConfig(ctx); !appendDiagsHasErr(diags, d) {
		cfg.AWS = c
	}
	if c, d := gcp.ToConfig(ctx); !appendDiagsHasErr(diags, d) {
		cfg.GCP = c
	}
	if c, d := azure.ToConfig(ctx); !appendDiagsHasErr(diags, d) {
		cfg.Azure = c
	}
	if c, d := age.ToConfig(ctx); !appendDiagsHasErr(diags, d) {
		cfg.Age = c
	}
	if c, d := pgp.ToConfig(ctx); !appendDiagsHasErr(diags, d) {
		cfg.PGP = c
	}
	return cfg
}
