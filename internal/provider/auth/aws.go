package auth

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	fwpath "github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	epschema "github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
)

// AWSModel is the terraform-plugin-framework data model for the `aws { ... }` block.
// Used by both the provider block and per-resource override blocks.
type AWSModel struct {
	Profile                types.String        `tfsdk:"profile"`
	Region                 types.String        `tfsdk:"region"`
	SharedConfigFiles      types.List          `tfsdk:"shared_config_files"`
	SharedCredentialsFiles types.List          `tfsdk:"shared_credentials_files"`
	Env                    types.Map           `tfsdk:"env"`
	AssumeRole             *AWSAssumeRoleModel `tfsdk:"assume_role"`
}

// AWSAssumeRoleModel is the terraform-plugin-framework data model for the nested
// `assume_role { ... }` block inside `aws { ... }`.
type AWSAssumeRoleModel struct {
	RoleARN     types.String `tfsdk:"role_arn"`
	SessionName types.String `tfsdk:"session_name"`
	ExternalID  types.String `tfsdk:"external_id"`
	Duration    types.String `tfsdk:"duration"`
}

// AWSBlockSchema returns the framework Schema definition for the `aws` nested block.
// Reused by the provider block schema and per-data-source override schemas.
func AWSBlockSchema() schema.Block {
	return schema.SingleNestedBlock{
		Description: "AWS KMS credential configuration.",
		Attributes: map[string]schema.Attribute{
			"profile":                  schema.StringAttribute{Optional: true},
			"region":                   schema.StringAttribute{Optional: true},
			"shared_config_files":      schema.ListAttribute{Optional: true, ElementType: types.StringType},
			"shared_credentials_files": schema.ListAttribute{Optional: true, ElementType: types.StringType},
			"env":                      schema.MapAttribute{Optional: true, ElementType: types.StringType},
		},
		Blocks: map[string]schema.Block{
			"assume_role": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"role_arn":     schema.StringAttribute{Optional: true},
					"session_name": schema.StringAttribute{Optional: true},
					"external_id":  schema.StringAttribute{Optional: true},
					"duration":     schema.StringAttribute{Optional: true},
				},
			},
		},
	}
}

// AWSBlockSchemaForDataSource returns the datasource/schema Block for the `aws` nested block.
// Mirrors AWSBlockSchema() but uses the datasource/schema type hierarchy.
func AWSBlockSchemaForDataSource() dsschema.Block {
	return dsschema.SingleNestedBlock{
		Description: "Per-resource AWS KMS credential override.",
		Attributes: map[string]dsschema.Attribute{
			"profile":                  dsschema.StringAttribute{Optional: true},
			"region":                   dsschema.StringAttribute{Optional: true},
			"shared_config_files":      dsschema.ListAttribute{Optional: true, ElementType: types.StringType},
			"shared_credentials_files": dsschema.ListAttribute{Optional: true, ElementType: types.StringType},
			"env":                      dsschema.MapAttribute{Optional: true, ElementType: types.StringType},
		},
		Blocks: map[string]dsschema.Block{
			"assume_role": dsschema.SingleNestedBlock{
				Attributes: map[string]dsschema.Attribute{
					"role_arn":     dsschema.StringAttribute{Optional: true},
					"session_name": dsschema.StringAttribute{Optional: true},
					"external_id":  dsschema.StringAttribute{Optional: true},
					"duration":     dsschema.StringAttribute{Optional: true},
				},
			},
		},
	}
}

// AWSBlockSchemaForEphemeral returns the ephemeral/schema Block for the `aws` nested block.
// Mirrors AWSBlockSchemaForDataSource() but uses the ephemeral/schema type hierarchy.
func AWSBlockSchemaForEphemeral() epschema.Block {
	return epschema.SingleNestedBlock{
		Description: "Per-resource AWS KMS credential override.",
		Attributes: map[string]epschema.Attribute{
			"profile":                  epschema.StringAttribute{Optional: true},
			"region":                   epschema.StringAttribute{Optional: true},
			"shared_config_files":      epschema.ListAttribute{Optional: true, ElementType: types.StringType},
			"shared_credentials_files": epschema.ListAttribute{Optional: true, ElementType: types.StringType},
			"env":                      epschema.MapAttribute{Optional: true, ElementType: types.StringType},
		},
		Blocks: map[string]epschema.Block{
			"assume_role": epschema.SingleNestedBlock{
				Attributes: map[string]epschema.Attribute{
					"role_arn":     epschema.StringAttribute{Optional: true},
					"session_name": epschema.StringAttribute{Optional: true},
					"external_id":  epschema.StringAttribute{Optional: true},
					"duration":     epschema.StringAttribute{Optional: true},
				},
			},
		},
	}
}

// ToConfig converts the framework data model into the package's AWSConfig value type.
// Nil receiver returns the zero value with no diagnostics.
func (m *AWSModel) ToConfig(ctx context.Context) (AWSConfig, diag.Diagnostics) {
	if m == nil {
		return AWSConfig{}, nil
	}
	var diags diag.Diagnostics
	cfg := AWSConfig{
		Profile: m.Profile.ValueString(),
		Region:  m.Region.ValueString(),
	}
	if !m.SharedConfigFiles.IsNull() {
		var s []string
		diags.Append(m.SharedConfigFiles.ElementsAs(ctx, &s, false)...)
		cfg.SharedConfigFiles = s
	}
	if !m.SharedCredentialsFiles.IsNull() {
		var s []string
		diags.Append(m.SharedCredentialsFiles.ElementsAs(ctx, &s, false)...)
		cfg.SharedCredentialsFiles = s
	}
	if !m.Env.IsNull() {
		var em map[string]string
		diags.Append(m.Env.ElementsAs(ctx, &em, false)...)
		cfg.Env = em
	}
	if m.AssumeRole != nil {
		ar := AWSAssumeRole{
			RoleARN:     m.AssumeRole.RoleARN.ValueString(),
			SessionName: m.AssumeRole.SessionName.ValueString(),
			ExternalID:  m.AssumeRole.ExternalID.ValueString(),
		}
		if d := m.AssumeRole.Duration.ValueString(); d != "" {
			dur, err := time.ParseDuration(d)
			if err != nil {
				diags.AddAttributeError(
					path("assume_role", "duration"),
					"invalid duration",
					"could not parse aws.assume_role.duration: "+err.Error(),
				)
			}
			ar.Duration = dur
		}
		cfg.AssumeRole = &ar
	}
	return cfg, diags
}

// path is a tiny helper to construct attribute paths for diagnostics.
func path(parts ...string) fwpath.Path {
	p := fwpath.Empty()
	for _, part := range parts {
		p = p.AtName(part)
	}
	return p
}
