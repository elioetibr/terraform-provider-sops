package auth

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
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

// AgeBlockSchemaForDataSource returns the datasource/schema Block for the `age` nested block.
// Mirrors AgeBlockSchema() but uses the datasource/schema type hierarchy.
func AgeBlockSchemaForDataSource() dsschema.Block {
	return dsschema.SingleNestedBlock{
		Description: "Per-resource age key override.",
		Attributes: map[string]dsschema.Attribute{
			"key":                  dsschema.StringAttribute{Optional: true, Sensitive: true},
			"key_file":             dsschema.StringAttribute{Optional: true},
			"key_command":          dsschema.StringAttribute{Optional: true},
			"ssh_private_key_file": dsschema.StringAttribute{Optional: true},
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
