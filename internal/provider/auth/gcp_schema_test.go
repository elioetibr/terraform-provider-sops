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

var gcpAttrs = []string{
	"credentials", "credentials_file", "impersonate_service_account", "quota_project",
}

func TestGCPBlockSchema_Provider(t *testing.T) {
	t.Parallel()
	s, ok := auth.GCPBlockSchema().(schema.SingleNestedBlock)
	require.True(t, ok)
	require.NotEmpty(t, s.Description)
	for _, a := range gcpAttrs {
		_, present := s.Attributes[a]
		require.True(t, present, "missing %q", a)
	}
}

func TestGCPBlockSchema_DataSource(t *testing.T) {
	t.Parallel()
	s, ok := auth.GCPBlockSchemaForDataSource().(dsschema.SingleNestedBlock)
	require.True(t, ok)
	for _, a := range gcpAttrs {
		_, present := s.Attributes[a]
		require.True(t, present, "missing %q", a)
	}
}

func TestGCPBlockSchema_Resource(t *testing.T) {
	t.Parallel()
	s, ok := auth.GCPBlockSchemaForResource().(rschema.SingleNestedBlock)
	require.True(t, ok)
	for _, a := range gcpAttrs {
		_, present := s.Attributes[a]
		require.True(t, present, "missing %q", a)
	}
}

func TestGCPBlockSchema_Ephemeral(t *testing.T) {
	t.Parallel()
	s, ok := auth.GCPBlockSchemaForEphemeral().(epschema.SingleNestedBlock)
	require.True(t, ok)
	for _, a := range gcpAttrs {
		_, present := s.Attributes[a]
		require.True(t, present, "missing %q", a)
	}
}
