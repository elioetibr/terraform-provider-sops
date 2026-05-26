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

func TestPGPBlockSchema_Provider(t *testing.T) {
	t.Parallel()
	s, ok := auth.PGPBlockSchema().(schema.SingleNestedBlock)
	require.True(t, ok)
	require.NotEmpty(t, s.Description)
	_, present := s.Attributes["gnupg_home"]
	require.True(t, present)
}

func TestPGPBlockSchema_DataSource(t *testing.T) {
	t.Parallel()
	s, ok := auth.PGPBlockSchemaForDataSource().(dsschema.SingleNestedBlock)
	require.True(t, ok)
	_, present := s.Attributes["gnupg_home"]
	require.True(t, present)
}

func TestPGPBlockSchema_Resource(t *testing.T) {
	t.Parallel()
	s, ok := auth.PGPBlockSchemaForResource().(rschema.SingleNestedBlock)
	require.True(t, ok)
	_, present := s.Attributes["gnupg_home"]
	require.True(t, present)
}

func TestPGPBlockSchema_Ephemeral(t *testing.T) {
	t.Parallel()
	s, ok := auth.PGPBlockSchemaForEphemeral().(epschema.SingleNestedBlock)
	require.True(t, ok)
	_, present := s.Attributes["gnupg_home"]
	require.True(t, present)
}
