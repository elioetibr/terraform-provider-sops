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

var azureAttrs = []string{
	"tenant_id", "client_id", "client_secret",
	"use_msi", "use_oidc", "use_workload_identity", "use_cli",
}

func TestAzureBlockSchema_Provider(t *testing.T) {
	t.Parallel()
	s, ok := auth.AzureBlockSchema().(schema.SingleNestedBlock)
	require.True(t, ok)
	require.NotEmpty(t, s.Description)
	for _, a := range azureAttrs {
		_, present := s.Attributes[a]
		require.True(t, present, "missing %q", a)
	}
}

func TestAzureBlockSchema_DataSource(t *testing.T) {
	t.Parallel()
	s, ok := auth.AzureBlockSchemaForDataSource().(dsschema.SingleNestedBlock)
	require.True(t, ok)
	for _, a := range azureAttrs {
		_, present := s.Attributes[a]
		require.True(t, present, "missing %q", a)
	}
}

func TestAzureBlockSchema_Resource(t *testing.T) {
	t.Parallel()
	s, ok := auth.AzureBlockSchemaForResource().(rschema.SingleNestedBlock)
	require.True(t, ok)
	for _, a := range azureAttrs {
		_, present := s.Attributes[a]
		require.True(t, present, "missing %q", a)
	}
}

func TestAzureBlockSchema_Ephemeral(t *testing.T) {
	t.Parallel()
	s, ok := auth.AzureBlockSchemaForEphemeral().(epschema.SingleNestedBlock)
	require.True(t, ok)
	for _, a := range azureAttrs {
		_, present := s.Attributes[a]
		require.True(t, present, "missing %q", a)
	}
}
