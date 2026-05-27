package sopswrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	sops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/version"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

// EncryptInput is the request to Encrypt.
type EncryptInput struct {
	Plaintext []byte
	Format    Format
	Rules     auth.CreationRules
	Config    auth.Config
}

// EncryptResult is what Encrypt returns.
type EncryptResult struct {
	Ciphertext []byte
	// CanonicalPlaintext is the parsed-then-emitted form of the plaintext.
	// This matches what Decrypt would later produce, so a SHA-256 over it is
	// stable across encrypt/decrypt round-trips (Stable drift fingerprint).
	CanonicalPlaintext []byte
	Metadata           Metadata
}

// Encrypt loads plaintext, constructs master keys with injected credentials,
// generates a data key, encrypts the tree, and returns ciphertext.
func Encrypt(ctx context.Context, in EncryptInput) (*EncryptResult, error) {
	store, err := StoreFor(in.Format)
	if err != nil {
		return nil, err
	}
	return encryptWithStore(ctx, store, in)
}

// encryptWithStore is the core encryption flow with an injectable Store. The
// public Encrypt looks up the Store from in.Format and delegates here; internal
// tests can pass a stub Store that fails at a specific step (LoadPlainFile,
// EmitPlainFile, EmitEncryptedFile) to exercise the defensive error branches
// that the real yaml/json/dotenv/ini/binary stores never trigger from real
// inputs.
func encryptWithStore(ctx context.Context, store Store, in EncryptInput) (*EncryptResult, error) {
	rel, err := getSem().Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: acquire semaphore: %w", err)
	}
	defer rel()

	restore := applyScopedEnv(in.Config)
	defer restore()

	branches, err := store.LoadPlainFile(in.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: load plaintext: %w", err)
	}

	canonical, err := store.EmitPlainFile(branches)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: emit canonical plaintext: %w", err)
	}

	groups, err := BuildMasterKeysFromRules(in.Rules, in.Config)
	if err != nil {
		return nil, err
	}

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups:         groups,
			Version:           version.Version,
			LastModified:      time.Now().UTC(),
			EncryptedSuffix:   in.Rules.EncryptedSuffix,
			UnencryptedSuffix: in.Rules.UnencryptedSuffix,
			EncryptedRegex:    in.Rules.EncryptedRegex,
			UnencryptedRegex:  in.Rules.UnencryptedRegex,
			ShamirThreshold:   in.Rules.Threshold,
		},
	}

	ks := []keyservice.KeyServiceClient{keyservice.NewLocalClient()}
	dataKey, errs := tree.GenerateDataKeyWithKeyServices(ks)
	if len(errs) > 0 {
		return nil, fmt.Errorf("sopswrap: generate data key: %w", errors.Join(errs...))
	}

	out, err := sealTree(&tree, dataKey, store)
	if err != nil {
		return nil, err
	}

	return &EncryptResult{
		Ciphertext:         out,
		CanonicalPlaintext: canonical,
		Metadata:           ExtractMetadata(tree),
	}, nil
}

// sealTree wraps sealTreeWithCipher using the production AES cipher. The
// indirection lets internal tests substitute a stub Cipher that fails after
// the tree.Encrypt step succeeds, exercising the MAC-encrypt error path that
// the real aes cipher never reaches with valid inputs.
func sealTree(tree *sops.Tree, dataKey []byte, store Store) ([]byte, error) {
	return sealTreeWithCipher(tree, dataKey, store, aes.NewCipher())
}

// sealTreeWithCipher performs the three SOPS-internal seal operations:
// encrypt every branch value with the data key, encrypt the resulting MAC,
// and emit the ciphertext via the store. Cipher is injectable so tests can
// force a failure at the MAC step.
func sealTreeWithCipher(tree *sops.Tree, dataKey []byte, store Store, cipher sops.Cipher) ([]byte, error) {
	mac, err := tree.Encrypt(dataKey, cipher)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: encrypt tree: %w", err)
	}
	encryptedMAC, err := cipher.Encrypt(mac, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("sopswrap: encrypt mac: %w", err)
	}
	tree.Metadata.MessageAuthenticationCode = encryptedMAC

	out, err := store.EmitEncryptedFile(*tree)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: emit ciphertext: %w", err)
	}
	return out, nil
}
