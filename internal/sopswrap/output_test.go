package sopswrap_test

import (
	"encoding/json"
	"testing"

	sops "github.com/getsops/sops/v3"
	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

func TestFlatten_NestedMap(t *testing.T) {
	t.Parallel()
	tree := sops.TreeBranches{
		sops.TreeBranch{
			sops.TreeItem{Key: "database", Value: sops.TreeBranch{
				sops.TreeItem{Key: "host", Value: "db.example.com"},
				sops.TreeItem{Key: "password", Value: "hunter2"},
			}},
			sops.TreeItem{Key: "api_key", Value: "sk-test-12345"},
		},
	}
	flat := sopswrap.Flatten(tree)
	require.Equal(t, "db.example.com", flat["database.host"])
	require.Equal(t, "hunter2", flat["database.password"])
	require.Equal(t, "sk-test-12345", flat["api_key"])
}

func TestFlatten_List(t *testing.T) {
	t.Parallel()
	tree := sops.TreeBranches{
		sops.TreeBranch{
			sops.TreeItem{Key: "nested", Value: sops.TreeBranch{
				sops.TreeItem{Key: "list", Value: []interface{}{"one", "two"}},
			}},
		},
	}
	flat := sopswrap.Flatten(tree)
	require.Equal(t, "one", flat["nested.list.0"])
	require.Equal(t, "two", flat["nested.list.1"])
}

func TestToJSON_NestedMap(t *testing.T) {
	t.Parallel()
	tree := sops.TreeBranches{
		sops.TreeBranch{
			sops.TreeItem{Key: "a", Value: sops.TreeBranch{
				sops.TreeItem{Key: "b", Value: 42},
			}},
		},
	}
	js, err := sopswrap.ToJSON(tree)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(js, &parsed))
	require.Equal(t, float64(42), parsed["a"].(map[string]any)["b"])
}

func TestExtractMetadata_KMSARNs(t *testing.T) {
	t.Parallel()
	tree := sops.Tree{
		Metadata: sops.Metadata{
			Version: "3.10.0",
			KeyGroups: []sops.KeyGroup{
				// We don't construct real MasterKeys here; ExtractMetadata accesses
				// only fields the framework can serialize without crypto state.
			},
		},
	}
	meta := sopswrap.ExtractMetadata(tree)
	require.Equal(t, "3.10.0", meta.Version)
}
