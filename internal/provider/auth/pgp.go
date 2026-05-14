package auth

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	epschema "github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

// PGPModel is the terraform-plugin-framework data model for the `pgp { ... }` block.
type PGPModel struct {
	GnupgHome types.String `tfsdk:"gnupg_home"`
}

// PGPBlockSchema returns the framework Schema definition for the `pgp` nested block.
func PGPBlockSchema() schema.Block {
	return schema.SingleNestedBlock{
		Description: "PGP / GnuPG configuration.",
		Attributes: map[string]schema.Attribute{
			"gnupg_home": schema.StringAttribute{Optional: true},
		},
	}
}

// PGPBlockSchemaForDataSource returns the datasource/schema Block for the `pgp` nested block.
// Mirrors PGPBlockSchema() but uses the datasource/schema type hierarchy.
func PGPBlockSchemaForDataSource() dsschema.Block {
	return dsschema.SingleNestedBlock{
		Description: "Per-resource PGP / GnuPG override.",
		Attributes: map[string]dsschema.Attribute{
			"gnupg_home": dsschema.StringAttribute{Optional: true},
		},
	}
}

// PGPBlockSchemaForResource returns the resource/schema Block for the `pgp` nested block.
// Mirrors PGPBlockSchemaForDataSource() but uses the resource/schema type hierarchy.
func PGPBlockSchemaForResource() rschema.Block {
	return rschema.SingleNestedBlock{
		Description: "Per-resource PGP / GnuPG override.",
		Attributes: map[string]rschema.Attribute{
			"gnupg_home": rschema.StringAttribute{Optional: true},
		},
	}
}

// PGPBlockSchemaForEphemeral returns the ephemeral/schema Block for the `pgp` nested block.
// Mirrors PGPBlockSchemaForDataSource() but uses the ephemeral/schema type hierarchy.
func PGPBlockSchemaForEphemeral() epschema.Block {
	return epschema.SingleNestedBlock{
		Description: "Per-resource PGP / GnuPG override.",
		Attributes: map[string]epschema.Attribute{
			"gnupg_home": epschema.StringAttribute{Optional: true},
		},
	}
}

// ToConfig converts the framework data model into the package's PGPConfig value type.
// Nil receiver returns the zero value with no diagnostics.
func (m *PGPModel) ToConfig(_ context.Context) (PGPConfig, diag.Diagnostics) {
	if m == nil {
		return PGPConfig{}, nil
	}
	return PGPConfig{GnupgHome: m.GnupgHome.ValueString()}, nil
}
