package sopswrap

import (
	"context"
	"errors"
	"testing"
	"time"

	sops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

// testAgeRecipient is a well-known recipient used purely as input to
// BuildMasterKeysFromRules; the corresponding private key is not required
// because the seal step is short-circuited by stub injection in these tests.
const testAgeRecipient = "age14zq6sys37a63fgnmf76g4uge7rzdje3gw92gh0sndh7577dgvc8shk93k9"

// stubStore is a Store implementation whose methods delegate to per-test
// callbacks. Each callback defaults to a delegating call into the real YAML
// store so a test only overrides the one step it wants to fail.
type stubStore struct {
	realStore     Store
	loadPlainFile func([]byte) (sops.TreeBranches, error)
	emitPlainFile func(sops.TreeBranches) ([]byte, error)
	loadEncrypted func([]byte) (sops.Tree, error)
	emitEncrypted func(sops.Tree) ([]byte, error)
}

func newStubStore(t *testing.T) *stubStore {
	t.Helper()
	realStore, err := StoreFor(FormatYAML)
	require.NoError(t, err)
	s := &stubStore{realStore: realStore}
	s.loadPlainFile = realStore.LoadPlainFile
	s.emitPlainFile = realStore.EmitPlainFile
	s.loadEncrypted = realStore.LoadEncryptedFile
	s.emitEncrypted = realStore.EmitEncryptedFile
	return s
}

func (s *stubStore) LoadPlainFile(in []byte) (sops.TreeBranches, error) {
	return s.loadPlainFile(in)
}
func (s *stubStore) EmitPlainFile(b sops.TreeBranches) ([]byte, error) {
	return s.emitPlainFile(b)
}
func (s *stubStore) LoadEncryptedFile(in []byte) (sops.Tree, error) {
	return s.loadEncrypted(in)
}
func (s *stubStore) EmitEncryptedFile(t sops.Tree) ([]byte, error) {
	return s.emitEncrypted(t)
}

// TestEncryptWithStore_EmitCanonicalFails covers the partial+miss pair at
// encrypt.go:58-59 — `EmitPlainFile (canonical)` errors after `LoadPlainFile`
// succeeds. With a real yaml store this branch is unreachable from any input
// the loader accepts; the stub fails it directly.
func TestEncryptWithStore_EmitCanonicalFails(t *testing.T) {
	t.Parallel()
	store := newStubStore(t)
	synthetic := errors.New("synthetic emit canonical failure")
	store.emitPlainFile = func(sops.TreeBranches) ([]byte, error) {
		return nil, synthetic
	}

	_, err := encryptWithStore(context.Background(), store, EncryptInput{
		Plaintext: []byte("k: v\n"),
		Format:    FormatYAML,
		Rules:     auth.CreationRules{AgeRecipients: []string{testAgeRecipient}},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "emit canonical plaintext",
		"the wrapper at encrypt.go:59 must surface the canonical emit error")
	require.ErrorIs(t, err, synthetic)
}

// TestEncryptWithStore_SealTreePropagatesEmitCiphertextErr covers the
// partial+miss pair at encrypt.go:88-89 — Encrypt's sealTree wrapper passes
// through any sealTree error. The stub forces EmitEncryptedFile inside
// sealTree to fail; encryptWithStore returns the wrapped error and the
// outer wrapper line fires.
func TestEncryptWithStore_SealTreePropagatesEmitCiphertextErr(t *testing.T) {
	t.Parallel()
	store := newStubStore(t)
	synthetic := errors.New("synthetic ciphertext emit failure")
	store.emitEncrypted = func(sops.Tree) ([]byte, error) {
		return nil, synthetic
	}

	_, err := encryptWithStore(context.Background(), store, EncryptInput{
		Plaintext: []byte("k: v\n"),
		Format:    FormatYAML,
		Rules:     auth.CreationRules{AgeRecipients: []string{testAgeRecipient}},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "emit ciphertext",
		"the sealTree error must propagate through encryptWithStore at encrypt.go:88-89")
	require.ErrorIs(t, err, synthetic)
}

// macFailCipher delegates to a real cipher until N successful Encrypt calls
// have happened, then fails the next Encrypt — simulating a cipher whose MAC
// encryption step errors out after the tree-value encryption succeeds.
type macFailCipher struct {
	delegate     sops.Cipher
	successCount int
	limit        int
	fail         error
}

func (m *macFailCipher) Encrypt(plaintext any, key []byte, additionalData string) (string, error) {
	if m.successCount >= m.limit {
		return "", m.fail
	}
	m.successCount++
	return m.delegate.Encrypt(plaintext, key, additionalData)
}

func (m *macFailCipher) Decrypt(ciphertext string, key []byte, additionalData string) (any, error) {
	return m.delegate.Decrypt(ciphertext, key, additionalData)
}

// TestSealTreeWithCipher_MACEncryptFails covers the partial+miss pair at
// encrypt.go:110-111 — `cipher.Encrypt(mac, ...)` errors after `tree.Encrypt`
// succeeds. With the real AES cipher this branch is unreachable because if
// the dataKey was valid for tree.Encrypt it is also valid for MAC encrypt;
// the stub fails the MAC call directly.
func TestSealTreeWithCipher_MACEncryptFails(t *testing.T) {
	t.Parallel()
	// Tree with a single value: tree.Encrypt does exactly one cipher.Encrypt
	// call (limit=1), then the MAC encrypt is the second call which fails.
	tree := &sops.Tree{
		Branches: sops.TreeBranches{
			sops.TreeBranch{sops.TreeItem{Key: "k", Value: "v"}},
		},
		Metadata: sops.Metadata{LastModified: time.Now().UTC()},
	}
	store, err := StoreFor(FormatYAML)
	require.NoError(t, err)

	synthetic := errors.New("synthetic MAC encrypt failure")
	cipher := &macFailCipher{
		delegate: aes.NewCipher(),
		limit:    1,
		fail:     synthetic,
	}

	_, err = sealTreeWithCipher(tree, make([]byte, 32), store, cipher)
	require.Error(t, err)
	require.Contains(t, err.Error(), "encrypt mac",
		"the MAC error wrapper at encrypt.go:111 must surface")
	require.ErrorIs(t, err, synthetic)
}
