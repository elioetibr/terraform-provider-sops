package resources

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

// providerAccessorStub satisfies ProviderDataAccessor for testing the Configure
// happy-path branch (req.ProviderData is a real accessor and the type assertion
// succeeds).
type providerAccessorStub struct {
	cfg auth.Config
}

func (s providerAccessorStub) ProviderAuthConfig() auth.Config { return s.cfg }

func TestNewFileResource_ReturnsNonNil(t *testing.T) {
	t.Parallel()
	r := NewFileResource()
	require.NotNil(t, r)
	_, ok := r.(*fileResource)
	require.True(t, ok)
}

func TestFileResource_Metadata(t *testing.T) {
	t.Parallel()
	r := &fileResource{}
	var resp resource.MetadataResponse
	r.Metadata(context.Background(),
		resource.MetadataRequest{ProviderTypeName: "sops"},
		&resp)
	require.Equal(t, "sops_file", resp.TypeName)
}

func TestFileResource_Schema(t *testing.T) {
	t.Parallel()
	r := &fileResource{}
	var resp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &resp)

	require.NotEmpty(t, resp.Schema.Description)
	for _, key := range []string{
		"id", "path", "content_wo", "content_wo_version",
		"input_type", "rotate_keys", "plaintext_sha256",
		"sops_mac", "sops_last_modified", "metadata",
	} {
		_, present := resp.Schema.Attributes[key]
		require.True(t, present, "schema missing attribute %q", key)
	}
	for _, block := range []string{"aws", "gcp", "azure", "age", "pgp", "creation_rules"} {
		_, present := resp.Schema.Blocks[block]
		require.True(t, present, "schema missing block %q", block)
	}
}

// TestFileResource_ConfigureHappyPath covers the branch where ProviderData is a
// real ProviderDataAccessor — the type assertion succeeds and the provider
// config is captured.
func TestFileResource_ConfigureHappyPath(t *testing.T) {
	t.Parallel()
	stub := providerAccessorStub{cfg: auth.Config{AWS: auth.AWSConfig{Profile: "prod"}}}
	r := &fileResource{}
	r.Configure(context.Background(),
		resource.ConfigureRequest{ProviderData: stub},
		&resource.ConfigureResponse{})
	require.Equal(t, "prod", r.providerCfg.AWS.Profile,
		"Configure must capture the provider config from a real accessor")
}

func TestMetadataSchemaAttribute_HasAllFields(t *testing.T) {
	t.Parallel()
	a := metadataSchemaAttribute()
	nested, ok := a.(rschema.SingleNestedAttribute)
	require.True(t, ok)
	for _, k := range []string{
		"lastmodified", "mac", "version",
		"kms_arns", "gcp_kms_resources", "azure_kv_urls",
		"age_recipients", "pgp_fingerprints",
	} {
		_, present := nested.Attributes[k]
		require.True(t, present, "metadata attribute missing %q", k)
	}
}

// TestBuildPerCallConfig_AllNilModels covers the nil-receiver branches in each
// auth ToConfig — none emit diags and the returned cfg is the zero value.
func TestBuildPerCallConfig_AllNilModels(t *testing.T) {
	t.Parallel()
	var diags fwDiags
	cfg := buildPerCallConfig(context.Background(), nil, nil, nil, nil, nil, &diags)
	require.False(t, diags.HasError())
	require.Empty(t, cfg.AWS.Profile)
	require.Empty(t, cfg.GCP.CredentialsFile)
	require.Empty(t, cfg.PGP.GnupgHome)
}
