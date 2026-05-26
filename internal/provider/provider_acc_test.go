package provider_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/elioetibr/terraform-provider-sops/internal/provider"
)

var protoV6Factory = map[string]func() (tfprotov6.ProviderServer, error){
	"sops": providerserver.NewProtocol6WithError(provider.New("test")()),
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// .../internal/provider/provider_acc_test.go → repo root (3 dirs up)
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
}

// TestAccProvider_Configure_AllBlocks exercises provider Configure when the
// user populates every supported auth block (aws/gcp/azure/age/pgp) plus
// concurrency_limit. It also drives a data source so Configure's
// DataSourceData wiring path is reached.
func TestAccProvider_Configure_AllBlocks(t *testing.T) {
	root := repoRoot(t)
	keyFile := filepath.Join(root, "testdata/age-key.txt")
	fixture := filepath.Join(root, "testdata/secrets.yaml")
	t.Setenv("SOPS_AGE_KEY_FILE", keyFile)

	tf := `
provider "sops" {
  concurrency_limit = 2

  aws {
    profile = "noop"
    region  = "us-east-1"
  }
  gcp {
    credentials_file = "/nonexistent"
  }
  azure {
    tenant_id = "00000000-0000-0000-0000-000000000000"
  }
  age {
    key_file = "` + keyFile + `"
  }
  pgp {
    gnupg_home = "/tmp"
  }
}

data "sops_file" "x" {
  source_file = "` + fixture + `"
  input_type  = "yaml"
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factory,
		Steps: []resource.TestStep{
			{
				Config: tf,
				Check:  resource.TestCheckResourceAttrSet("data.sops_file.x", "data.database.password"),
			},
		},
	})
}
