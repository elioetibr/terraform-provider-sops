package provider_test

import (
	"context"
	"testing"

	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider"
)

func TestProviderBuilds(t *testing.T) {
	t.Parallel()
	p := provider.New("test")()
	require.NotNil(t, p, "provider must construct")
	_, err := providerserver.NewProtocol6WithError(p)()
	require.NoError(t, err)
}

func TestProviderSchemaHasAuthBlocks(t *testing.T) {
	t.Parallel()
	p := provider.New("test")()
	resp := &fwprovider.SchemaResponse{}
	p.Schema(context.Background(), fwprovider.SchemaRequest{}, resp)
	require.False(t, resp.Diagnostics.HasError(), resp.Diagnostics.Errors())

	require.Contains(t, resp.Schema.GetBlocks(), "aws")
	require.Contains(t, resp.Schema.GetBlocks(), "gcp")
	require.Contains(t, resp.Schema.GetBlocks(), "azure")
	require.Contains(t, resp.Schema.GetBlocks(), "age")
	require.Contains(t, resp.Schema.GetBlocks(), "pgp")
	require.Contains(t, resp.Schema.GetAttributes(), "concurrency_limit")
}
