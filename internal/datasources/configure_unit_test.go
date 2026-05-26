package datasources

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
)

// TestFileDataSource_ConfigureNilProviderData covers the early-return when the
// framework calls Configure before the provider's Configure has run.
func TestFileDataSource_ConfigureNilProviderData(t *testing.T) {
	t.Parallel()
	d := &fileDataSource{}
	d.Configure(context.Background(),
		datasource.ConfigureRequest{ProviderData: nil},
		&datasource.ConfigureResponse{})
}

// TestFileDataSource_ConfigureWrongType covers the cast-fail branch.
func TestFileDataSource_ConfigureWrongType(t *testing.T) {
	t.Parallel()
	d := &fileDataSource{}
	d.Configure(context.Background(),
		datasource.ConfigureRequest{ProviderData: "not-an-accessor"},
		&datasource.ConfigureResponse{})
}

// TestExternalDataSource_ConfigureNilProviderData covers the early-return.
func TestExternalDataSource_ConfigureNilProviderData(t *testing.T) {
	t.Parallel()
	d := &externalDataSource{}
	d.Configure(context.Background(),
		datasource.ConfigureRequest{ProviderData: nil},
		&datasource.ConfigureResponse{})
}

// TestExternalDataSource_ConfigureWrongType covers the cast-fail branch.
func TestExternalDataSource_ConfigureWrongType(t *testing.T) {
	t.Parallel()
	d := &externalDataSource{}
	d.Configure(context.Background(),
		datasource.ConfigureRequest{ProviderData: "not-an-accessor"},
		&datasource.ConfigureResponse{})
}
