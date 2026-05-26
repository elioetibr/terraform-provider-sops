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

var ageAttrs = []string{"key", "key_file", "key_command", "ssh_private_key_file"}

func TestAgeBlockSchema_Provider(t *testing.T) {
	t.Parallel()
	s, ok := auth.AgeBlockSchema().(schema.SingleNestedBlock)
	require.True(t, ok)
	require.NotEmpty(t, s.Description)
	for _, a := range ageAttrs {
		_, present := s.Attributes[a]
		require.True(t, present, "missing %q", a)
	}
}

func TestAgeBlockSchema_DataSource(t *testing.T) {
	t.Parallel()
	s, ok := auth.AgeBlockSchemaForDataSource().(dsschema.SingleNestedBlock)
	require.True(t, ok)
	require.NotEmpty(t, s.Description)
	for _, a := range ageAttrs {
		_, present := s.Attributes[a]
		require.True(t, present, "missing %q", a)
	}
}

func TestAgeBlockSchema_Resource(t *testing.T) {
	t.Parallel()
	s, ok := auth.AgeBlockSchemaForResource().(rschema.SingleNestedBlock)
	require.True(t, ok)
	require.NotEmpty(t, s.Description)
	for _, a := range ageAttrs {
		_, present := s.Attributes[a]
		require.True(t, present, "missing %q", a)
	}
}

func TestAgeBlockSchema_Ephemeral(t *testing.T) {
	t.Parallel()
	s, ok := auth.AgeBlockSchemaForEphemeral().(epschema.SingleNestedBlock)
	require.True(t, ok)
	require.NotEmpty(t, s.Description)
	for _, a := range ageAttrs {
		_, present := s.Attributes[a]
		require.True(t, present, "missing %q", a)
	}
}
