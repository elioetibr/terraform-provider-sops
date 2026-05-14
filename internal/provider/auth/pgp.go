package auth

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
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

// ToConfig converts the framework data model into the package's PGPConfig value type.
// Nil receiver returns the zero value with no diagnostics.
func (m *PGPModel) ToConfig(_ context.Context) (PGPConfig, diag.Diagnostics) {
	if m == nil {
		return PGPConfig{}, nil
	}
	return PGPConfig{GnupgHome: m.GnupgHome.ValueString()}, nil
}
