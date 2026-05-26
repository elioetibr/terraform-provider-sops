package auth_test

import (
	"testing"

	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	epschema "github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

var awsAttrs = []string{"profile", "region", "shared_config_files", "shared_credentials_files", "env"}
var awsAssumeRoleAttrs = []string{"role_arn", "session_name", "external_id", "duration"}

func TestAWSBlockSchema_Provider(t *testing.T) {
	t.Parallel()
	s, ok := auth.AWSBlockSchema().(schema.SingleNestedBlock)
	require.True(t, ok)
	require.NotEmpty(t, s.Description)
	for _, a := range awsAttrs {
		_, present := s.Attributes[a]
		require.True(t, present, "missing %q", a)
	}
	ar, present := s.Blocks["assume_role"]
	require.True(t, present, "missing assume_role block")
	arSingle, ok := ar.(schema.SingleNestedBlock)
	require.True(t, ok)
	for _, a := range awsAssumeRoleAttrs {
		_, present := arSingle.Attributes[a]
		require.True(t, present, "missing assume_role.%q", a)
	}
}

func TestAWSBlockSchema_DataSource(t *testing.T) {
	t.Parallel()
	s, ok := auth.AWSBlockSchemaForDataSource().(dsschema.SingleNestedBlock)
	require.True(t, ok)
	require.NotEmpty(t, s.Description)
	for _, a := range awsAttrs {
		_, present := s.Attributes[a]
		require.True(t, present, "missing %q", a)
	}
	ar, present := s.Blocks["assume_role"]
	require.True(t, present)
	arSingle, ok := ar.(dsschema.SingleNestedBlock)
	require.True(t, ok)
	for _, a := range awsAssumeRoleAttrs {
		_, present := arSingle.Attributes[a]
		require.True(t, present, "missing assume_role.%q", a)
	}
}

func TestAWSBlockSchema_Resource(t *testing.T) {
	t.Parallel()
	s, ok := auth.AWSBlockSchemaForResource().(rschema.SingleNestedBlock)
	require.True(t, ok)
	require.NotEmpty(t, s.Description)
	for _, a := range awsAttrs {
		_, present := s.Attributes[a]
		require.True(t, present, "missing %q", a)
	}
	ar, present := s.Blocks["assume_role"]
	require.True(t, present)
	arSingle, ok := ar.(rschema.SingleNestedBlock)
	require.True(t, ok)
	for _, a := range awsAssumeRoleAttrs {
		_, present := arSingle.Attributes[a]
		require.True(t, present, "missing assume_role.%q", a)
	}
}

func TestAWSBlockSchema_Ephemeral(t *testing.T) {
	t.Parallel()
	s, ok := auth.AWSBlockSchemaForEphemeral().(epschema.SingleNestedBlock)
	require.True(t, ok)
	require.NotEmpty(t, s.Description)
	for _, a := range awsAttrs {
		_, present := s.Attributes[a]
		require.True(t, present, "missing %q", a)
	}
	ar, present := s.Blocks["assume_role"]
	require.True(t, present)
	arSingle, ok := ar.(epschema.SingleNestedBlock)
	require.True(t, ok)
	for _, a := range awsAssumeRoleAttrs {
		_, present := arSingle.Attributes[a]
		require.True(t, present, "missing assume_role.%q", a)
	}
}
