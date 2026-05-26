package resources

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// TestFileResource_ConfigureNilProviderData exercises the early-return branch
// when the framework calls Configure before provider Configure has run.
func TestFileResource_ConfigureNilProviderData(t *testing.T) {
	t.Parallel()
	r := &fileResource{}
	r.Configure(context.Background(),
		resource.ConfigureRequest{ProviderData: nil},
		&resource.ConfigureResponse{})
	// No assertion: success is "no panic and no state mutation".
}

// TestFileResource_ConfigureWrongType covers the branch where the framework
// passes ProviderData but it does not implement ProviderDataAccessor.
// The expected behaviour is a silent no-op; the cast simply fails.
func TestFileResource_ConfigureWrongType(t *testing.T) {
	t.Parallel()
	r := &fileResource{}
	r.Configure(context.Background(),
		resource.ConfigureRequest{ProviderData: "not-an-accessor"},
		&resource.ConfigureResponse{})
}
