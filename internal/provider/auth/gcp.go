package auth

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	epschema "github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
)

// GCPModel is the terraform-plugin-framework data model for the `gcp { ... }` block.
type GCPModel struct {
	Credentials               types.String `tfsdk:"credentials"`
	CredentialsFile           types.String `tfsdk:"credentials_file"`
	ImpersonateServiceAccount types.String `tfsdk:"impersonate_service_account"`
	QuotaProject              types.String `tfsdk:"quota_project"`
}

// GCPBlockSchema returns the framework Schema definition for the `gcp` nested block.
func GCPBlockSchema() schema.Block {
	return schema.SingleNestedBlock{
		Description: "GCP KMS credential configuration.",
		Attributes: map[string]schema.Attribute{
			"credentials":                 schema.StringAttribute{Optional: true, Sensitive: true},
			"credentials_file":            schema.StringAttribute{Optional: true},
			"impersonate_service_account": schema.StringAttribute{Optional: true},
			"quota_project":               schema.StringAttribute{Optional: true},
		},
	}
}

// GCPBlockSchemaForDataSource returns the datasource/schema Block for the `gcp` nested block.
// Mirrors GCPBlockSchema() but uses the datasource/schema type hierarchy.
func GCPBlockSchemaForDataSource() dsschema.Block {
	return dsschema.SingleNestedBlock{
		Description: "Per-resource GCP KMS credential override.",
		Attributes: map[string]dsschema.Attribute{
			"credentials":                 dsschema.StringAttribute{Optional: true, Sensitive: true},
			"credentials_file":            dsschema.StringAttribute{Optional: true},
			"impersonate_service_account": dsschema.StringAttribute{Optional: true},
			"quota_project":               dsschema.StringAttribute{Optional: true},
		},
	}
}

// GCPBlockSchemaForEphemeral returns the ephemeral/schema Block for the `gcp` nested block.
// Mirrors GCPBlockSchemaForDataSource() but uses the ephemeral/schema type hierarchy.
func GCPBlockSchemaForEphemeral() epschema.Block {
	return epschema.SingleNestedBlock{
		Description: "Per-resource GCP KMS credential override.",
		Attributes: map[string]epschema.Attribute{
			"credentials":                 epschema.StringAttribute{Optional: true, Sensitive: true},
			"credentials_file":            epschema.StringAttribute{Optional: true},
			"impersonate_service_account": epschema.StringAttribute{Optional: true},
			"quota_project":               epschema.StringAttribute{Optional: true},
		},
	}
}

// ToConfig converts the framework data model into the package's GCPConfig value type.
// Nil receiver returns the zero value with no diagnostics.
func (m *GCPModel) ToConfig(_ context.Context) (GCPConfig, diag.Diagnostics) {
	if m == nil {
		return GCPConfig{}, nil
	}
	return GCPConfig{
		Credentials:               m.Credentials.ValueString(),
		CredentialsFile:           m.CredentialsFile.ValueString(),
		ImpersonateServiceAccount: m.ImpersonateServiceAccount.ValueString(),
		QuotaProject:              m.QuotaProject.ValueString(),
	}, nil
}
