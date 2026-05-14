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
	Metadata   Metadata
}

// Encrypt loads plaintext, constructs master keys with injected credentials,
// generates a data key, encrypts the tree, and returns ciphertext.
func Encrypt(ctx context.Context, in EncryptInput) (*EncryptResult, error) {
	rel, err := getSem().Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: acquire semaphore: %w", err)
	}
	defer rel()

	restore := applyScopedEnv(in.Config)
	defer restore()

	store, err := StoreFor(in.Format)
	if err != nil {
		return nil, err
	}

	branches, err := store.LoadPlainFile(in.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: load plaintext: %w", err)
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

	if _, err := tree.Encrypt(dataKey, aes.NewCipher()); err != nil {
		return nil, fmt.Errorf("sopswrap: encrypt tree: %w", err)
	}

	out, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: emit ciphertext: %w", err)
	}

	return &EncryptResult{
		Ciphertext: out,
		Metadata:   ExtractMetadata(tree),
	}, nil
}
