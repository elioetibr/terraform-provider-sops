package auth

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	provschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

// CreationRules holds the master-key list and content-rules a new sops file is
// encrypted with. Consumed by sopswrap.Encrypt.
type CreationRules struct {
	KMSARNs           []string
	GCPKMSResources   []string
	AzureKVKeys       []string
	AgeRecipients     []string
	PGPFingerprints   []string
	EncryptedRegex    string
	UnencryptedRegex  string
	EncryptedSuffix   string
	UnencryptedSuffix string
	Threshold         int
}

// HasAnyKey returns whether at least one key source is configured.
func (c CreationRules) HasAnyKey() bool {
	return len(c.KMSARNs) > 0 || len(c.GCPKMSResources) > 0 ||
		len(c.AzureKVKeys) > 0 || len(c.AgeRecipients) > 0 ||
		len(c.PGPFingerprints) > 0
}

// CreationRulesModel is the terraform-plugin-framework data model.
type CreationRulesModel struct {
	KMSARNs           types.List   `tfsdk:"kms_arns"`
	GCPKMSResources   types.List   `tfsdk:"gcp_kms_resources"`
	AzureKVKeys       types.List   `tfsdk:"azure_kv_keys"`
	AgeRecipients     types.List   `tfsdk:"age_recipients"`
	PGPFingerprints   types.List   `tfsdk:"pgp_fingerprints"`
	EncryptedRegex    types.String `tfsdk:"encrypted_regex"`
	UnencryptedRegex  types.String `tfsdk:"unencrypted_regex"`
	EncryptedSuffix   types.String `tfsdk:"encrypted_suffix"`
	UnencryptedSuffix types.String `tfsdk:"unencrypted_suffix"`
	Threshold         types.Int64  `tfsdk:"threshold"`
}

// ToConfig converts the framework model into the value type sopswrap consumes.
// Errors when no key source is configured (a creation_rules block with no
// recipients can never produce an encryptable file).
func (m *CreationRulesModel) ToConfig(ctx context.Context) (CreationRules, diag.Diagnostics) {
	if m == nil {
		return CreationRules{}, nil
	}
	var diags diag.Diagnostics
	out := CreationRules{
		EncryptedRegex:    m.EncryptedRegex.ValueString(),
		UnencryptedRegex:  m.UnencryptedRegex.ValueString(),
		EncryptedSuffix:   m.EncryptedSuffix.ValueString(),
		UnencryptedSuffix: m.UnencryptedSuffix.ValueString(),
		Threshold:         int(m.Threshold.ValueInt64()),
	}
	for ptr, list := range map[*[]string]types.List{
		&out.KMSARNs:         m.KMSARNs,
		&out.GCPKMSResources: m.GCPKMSResources,
		&out.AzureKVKeys:     m.AzureKVKeys,
		&out.AgeRecipients:   m.AgeRecipients,
		&out.PGPFingerprints: m.PGPFingerprints,
	} {
		if list.IsNull() || list.IsUnknown() {
			continue
		}
		var ss []string
		diags.Append(list.ElementsAs(ctx, &ss, false)...)
		*ptr = ss
	}
	if diags.HasError() {
		return out, diags
	}
	if !out.HasAnyKey() {
		diags.AddError(
			"creation_rules requires at least one key source",
			"Set kms_arns, gcp_kms_resources, azure_kv_keys, age_recipients, or pgp_fingerprints.",
		)
	}
	return out, diags
}

// CreationRulesProviderBlockSchema is the schema for the provider-block variant
// (currently unused — kept for symmetry with other auth blocks; provider-level
// creation_rules may land in a later phase).
func CreationRulesProviderBlockSchema() provschema.Block {
	return provschema.SingleNestedBlock{
		Description: "Default creation rules for new encrypted files.",
		Attributes:  creationRulesProviderAttrs(),
	}
}

// CreationRulesResourceBlockSchema is the schema for the resource-level block.
// This is the one actually used today.
func CreationRulesResourceBlockSchema() rschema.Block {
	return rschema.SingleNestedBlock{
		Description: "Master keys + content rules used when encrypting this file.",
		Attributes: map[string]rschema.Attribute{
			"kms_arns":           rschema.ListAttribute{Optional: true, ElementType: types.StringType},
			"gcp_kms_resources":  rschema.ListAttribute{Optional: true, ElementType: types.StringType},
			"azure_kv_keys":      rschema.ListAttribute{Optional: true, ElementType: types.StringType},
			"age_recipients":     rschema.ListAttribute{Optional: true, ElementType: types.StringType},
			"pgp_fingerprints":   rschema.ListAttribute{Optional: true, ElementType: types.StringType},
			"encrypted_regex":    rschema.StringAttribute{Optional: true},
			"unencrypted_regex":  rschema.StringAttribute{Optional: true},
			"encrypted_suffix":   rschema.StringAttribute{Optional: true},
			"unencrypted_suffix": rschema.StringAttribute{Optional: true},
			"threshold":          rschema.Int64Attribute{Optional: true},
		},
	}
}

func creationRulesProviderAttrs() map[string]provschema.Attribute {
	return map[string]provschema.Attribute{
		"kms_arns":           provschema.ListAttribute{Optional: true, ElementType: types.StringType},
		"gcp_kms_resources":  provschema.ListAttribute{Optional: true, ElementType: types.StringType},
		"azure_kv_keys":      provschema.ListAttribute{Optional: true, ElementType: types.StringType},
		"age_recipients":     provschema.ListAttribute{Optional: true, ElementType: types.StringType},
		"pgp_fingerprints":   provschema.ListAttribute{Optional: true, ElementType: types.StringType},
		"encrypted_regex":    provschema.StringAttribute{Optional: true},
		"unencrypted_regex":  provschema.StringAttribute{Optional: true},
		"encrypted_suffix":   provschema.StringAttribute{Optional: true},
		"unencrypted_suffix": provschema.StringAttribute{Optional: true},
		"threshold":          provschema.Int64Attribute{Optional: true},
	}
}
