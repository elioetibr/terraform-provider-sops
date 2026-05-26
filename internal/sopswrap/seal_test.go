package sopswrap

import (
	"testing"
	"time"

	sops "github.com/getsops/sops/v3"
	"github.com/stretchr/testify/require"
)

// TestSealTree_DotenvWithNestedBranchTriggersEmitErr: the dotenv store cannot
// emit nested branches (it expects a flat KEY=VALUE shape). After tree.Encrypt
// + cipher.Encrypt succeed, EmitEncryptedFile errors out. Covers the third
// defensive branch in sealTree.
func TestSealTree_DotenvWithNestedBranchTriggersEmitErr(t *testing.T) {
	t.Parallel()
	tree := &sops.Tree{
		Branches: sops.TreeBranches{
			sops.TreeBranch{
				sops.TreeItem{Key: "outer", Value: sops.TreeBranch{
					sops.TreeItem{Key: "inner", Value: "v"},
				}},
			},
		},
		Metadata: sops.Metadata{LastModified: time.Now().UTC()},
	}
	store, err := StoreFor(FormatDotenv)
	require.NoError(t, err)

	// 32-byte dataKey: tree.Encrypt + cipher.Encrypt MAC succeed.
	dataKey := make([]byte, 32)
	_, err = sealTree(tree, dataKey, store)
	require.Error(t, err, "dotenv emit must reject nested branches")
}

// TestSealTree_BadDataKeyTriggersTreeEncryptErr covers the tree.Encrypt error
// branch in sealTree: AES requires a 16/24/32-byte key, so a 1-byte dataKey
// makes the underlying aes.NewCipher fail and the error propagates back.
func TestSealTree_BadDataKeyTriggersTreeEncryptErr(t *testing.T) {
	t.Parallel()
	tree := &sops.Tree{
		Branches: sops.TreeBranches{
			sops.TreeBranch{sops.TreeItem{Key: "k", Value: "v"}},
		},
		Metadata: sops.Metadata{LastModified: time.Now().UTC()},
	}
	store, err := StoreFor(FormatYAML)
	require.NoError(t, err)

	_, err = sealTree(tree, []byte{0x00}, store)
	require.Error(t, err, "1-byte dataKey must fail AES key construction inside tree.Encrypt")
}
