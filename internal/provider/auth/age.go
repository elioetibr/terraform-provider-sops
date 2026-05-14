package auth

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// AgeModel is the terraform-plugin-framework data model for the `age { ... }` block.
type AgeModel struct {
	Key               types.String `tfsdk:"key"`
	KeyFile           types.String `tfsdk:"key_file"`
	KeyCommand        types.String `tfsdk:"key_command"`
	SSHPrivateKeyFile types.String `tfsdk:"ssh_private_key_file"`
}

// AgeBlockSchema returns the framework Schema definition for the `age` nested block.
func AgeBlockSchema() schema.Block {
	return schema.SingleNestedBlock{
		Description: "age key configuration.",
		Attributes: map[string]schema.Attribute{
			"key":                  schema.StringAttribute{Optional: true, Sensitive: true},
			"key_file":             schema.StringAttribute{Optional: true},
			"key_command":          schema.StringAttribute{Optional: true},
			"ssh_private_key_file": schema.StringAttribute{Optional: true},
		},
	}
}

// ToConfig converts the framework data model into the package's AgeConfig value type.
// Nil receiver returns the zero value with no diagnostics.
func (m *AgeModel) ToConfig(_ context.Context) (AgeConfig, diag.Diagnostics) {
	if m == nil {
		return AgeConfig{}, nil
	}
	return AgeConfig{
		Key:               m.Key.ValueString(),
		KeyFile:           m.KeyFile.ValueString(),
		KeyCommand:        m.KeyCommand.ValueString(),
		SSHPrivateKeyFile: m.SSHPrivateKeyFile.ValueString(),
	}, nil
}
