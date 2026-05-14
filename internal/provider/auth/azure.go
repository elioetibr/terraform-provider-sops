package auth

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
)

// AzureModel is the terraform-plugin-framework data model for the `azure { ... }` block.
type AzureModel struct {
	TenantID            types.String `tfsdk:"tenant_id"`
	ClientID            types.String `tfsdk:"client_id"`
	ClientSecret        types.String `tfsdk:"client_secret"`
	UseMSI              types.Bool   `tfsdk:"use_msi"`
	UseOIDC             types.Bool   `tfsdk:"use_oidc"`
	UseWorkloadIdentity types.Bool   `tfsdk:"use_workload_identity"`
	UseCLI              types.Bool   `tfsdk:"use_cli"`
}

// AzureBlockSchema returns the framework Schema definition for the `azure` nested block.
func AzureBlockSchema() schema.Block {
	return schema.SingleNestedBlock{
		Description: "Azure Key Vault credential configuration.",
		Attributes: map[string]schema.Attribute{
			"tenant_id":             schema.StringAttribute{Optional: true},
			"client_id":             schema.StringAttribute{Optional: true},
			"client_secret":         schema.StringAttribute{Optional: true, Sensitive: true},
			"use_msi":               schema.BoolAttribute{Optional: true},
			"use_oidc":              schema.BoolAttribute{Optional: true},
			"use_workload_identity": schema.BoolAttribute{Optional: true},
			"use_cli":               schema.BoolAttribute{Optional: true},
		},
	}
}

// AzureBlockSchemaForDataSource returns the datasource/schema Block for the `azure` nested block.
// Mirrors AzureBlockSchema() but uses the datasource/schema type hierarchy.
func AzureBlockSchemaForDataSource() dsschema.Block {
	return dsschema.SingleNestedBlock{
		Description: "Per-resource Azure Key Vault credential override.",
		Attributes: map[string]dsschema.Attribute{
			"tenant_id":             dsschema.StringAttribute{Optional: true},
			"client_id":             dsschema.StringAttribute{Optional: true},
			"client_secret":         dsschema.StringAttribute{Optional: true, Sensitive: true},
			"use_msi":               dsschema.BoolAttribute{Optional: true},
			"use_oidc":              dsschema.BoolAttribute{Optional: true},
			"use_workload_identity": dsschema.BoolAttribute{Optional: true},
			"use_cli":               dsschema.BoolAttribute{Optional: true},
		},
	}
}

// ToConfig converts the framework data model into the package's AzureConfig value type.
// Nil receiver returns the zero value with no diagnostics.
func (m *AzureModel) ToConfig(_ context.Context) (AzureConfig, diag.Diagnostics) {
	if m == nil {
		return AzureConfig{}, nil
	}
	return AzureConfig{
		TenantID:            m.TenantID.ValueString(),
		ClientID:            m.ClientID.ValueString(),
		ClientSecret:        m.ClientSecret.ValueString(),
		UseMSI:              m.UseMSI.ValueBool(),
		UseOIDC:             m.UseOIDC.ValueBool(),
		UseWorkloadIdentity: m.UseWorkloadIdentity.ValueBool(),
		UseCLI:              m.UseCLI.ValueBool(),
	}, nil
}
