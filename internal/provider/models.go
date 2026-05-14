package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

// ProviderModel is the framework data model for the `provider "sops" { ... }` block.
type ProviderModel struct {
	AWS              *auth.AWSModel   `tfsdk:"aws"`
	GCP              *auth.GCPModel   `tfsdk:"gcp"`
	Azure            *auth.AzureModel `tfsdk:"azure"`
	Age              *auth.AgeModel   `tfsdk:"age"`
	PGP              *auth.PGPModel   `tfsdk:"pgp"`
	ConcurrencyLimit types.Int64      `tfsdk:"concurrency_limit"`
}
