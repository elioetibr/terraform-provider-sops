package provider_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/stretchr/testify/require"

	"github.com/elioseverojunior/terraform-provider-sops/internal/provider"
)

func TestProviderBuilds(t *testing.T) {
	t.Parallel()
	p := provider.New("test")()
	require.NotNil(t, p, "provider must construct")
	_, err := providerserver.NewProtocol6WithError(p)()
	require.NoError(t, err)
	_ = context.Background()
}
