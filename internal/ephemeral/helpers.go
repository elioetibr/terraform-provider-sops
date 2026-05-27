// Package ephemeral implements ephemeral resources that expose decrypted SOPS
// values without serialising plaintext to plan or state.
package ephemeral

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	epschema "github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

// ProviderDataAccessor is what the provider hands us via EphemeralResourceData.
type ProviderDataAccessor interface {
	ProviderAuthConfig() auth.Config
}

// metadataAttribute returns the ephemeral/schema nested attribute for sops metadata.
func metadataAttribute() epschema.SingleNestedAttribute {
	return epschema.SingleNestedAttribute{
		Computed: true,
		Attributes: map[string]epschema.Attribute{
			"lastmodified":      epschema.StringAttribute{Computed: true},
			"mac":               epschema.StringAttribute{Computed: true, Sensitive: true},
			"version":           epschema.StringAttribute{Computed: true},
			"kms_arns":          epschema.ListAttribute{Computed: true, ElementType: types.StringType},
			"gcp_kms_resources": epschema.ListAttribute{Computed: true, ElementType: types.StringType},
			"azure_kv_urls":     epschema.ListAttribute{Computed: true, ElementType: types.StringType},
			"age_recipients":    epschema.ListAttribute{Computed: true, ElementType: types.StringType},
			"pgp_fingerprints":  epschema.ListAttribute{Computed: true, ElementType: types.StringType},
		},
	}
}

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
	t := metadataAttrTypes()
	o, _ := types.ObjectValue(t, attrs)
	return o
}

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

func listOfStrings(_ context.Context, ss []string) types.List {
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

// buildPerCallConfigEphemeral converts per-resource auth model overrides into
// an auth.Config. Analogous to datasources.buildPerCallConfig but lives in
// this package so ephemeral resources do not import the datasources package.
func buildPerCallConfigEphemeral(
	ctx context.Context,
	aws *auth.AWSModel,
	gcp *auth.GCPModel,
	azure *auth.AzureModel,
	age *auth.AgeModel,
	pgp *auth.PGPModel,
	diags *diag.Diagnostics,
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

func appendDiagsHasErr(out *diag.Diagnostics, in diag.Diagnostics) bool {
	out.Append(in...)
	return in.HasError()
}
