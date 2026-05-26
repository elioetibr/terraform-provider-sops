package ephemeral

import (
	"context"
	"testing"

	fwephemeral "github.com/hashicorp/terraform-plugin-framework/ephemeral"
)

// TestFileEphemeral_ConfigureNilProviderData covers the early-return when the
// framework calls Configure before the provider's Configure has run.
func TestFileEphemeral_ConfigureNilProviderData(t *testing.T) {
	t.Parallel()
	e := &fileEphemeral{}
	e.Configure(context.Background(),
		fwephemeral.ConfigureRequest{ProviderData: nil},
		&fwephemeral.ConfigureResponse{})
}

// TestFileEphemeral_ConfigureWrongType covers the cast-fail branch.
func TestFileEphemeral_ConfigureWrongType(t *testing.T) {
	t.Parallel()
	e := &fileEphemeral{}
	e.Configure(context.Background(),
		fwephemeral.ConfigureRequest{ProviderData: "not-an-accessor"},
		&fwephemeral.ConfigureResponse{})
}

// TestExternalEphemeral_ConfigureNilProviderData covers the early-return.
func TestExternalEphemeral_ConfigureNilProviderData(t *testing.T) {
	t.Parallel()
	e := &externalEphemeral{}
	e.Configure(context.Background(),
		fwephemeral.ConfigureRequest{ProviderData: nil},
		&fwephemeral.ConfigureResponse{})
}

// TestExternalEphemeral_ConfigureWrongType covers the cast-fail branch.
func TestExternalEphemeral_ConfigureWrongType(t *testing.T) {
	t.Parallel()
	e := &externalEphemeral{}
	e.Configure(context.Background(),
		fwephemeral.ConfigureRequest{ProviderData: "not-an-accessor"},
		&fwephemeral.ConfigureResponse{})
}
