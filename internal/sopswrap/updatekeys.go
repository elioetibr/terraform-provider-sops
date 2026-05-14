package sopswrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	sops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/keyservice"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

// UpdateKeysInput is the request to UpdateKeys.
type UpdateKeysInput struct {
	Source   []byte
	Format   Format
	NewRules auth.CreationRules
	Config   auth.Config
}

// UpdateKeysResult is what UpdateKeys returns.
type UpdateKeysResult struct {
	Ciphertext []byte
	Metadata   Metadata
}

// UpdateKeys rotates the master-key list on an encrypted file without
// re-encrypting the file's plaintext content. Mirrors `sops updatekeys`.
func UpdateKeys(ctx context.Context, in UpdateKeysInput) (*UpdateKeysResult, error) {
	rel, err := getSem().Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer rel()

	restore := applyScopedEnv(in.Config)
	defer restore()

	store, err := StoreFor(in.Format)
	if err != nil {
		return nil, err
	}

	tree, err := store.LoadEncryptedFile(in.Source)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: load encrypted: %w", err)
	}

	// Decrypt the existing data key via the existing master keys.
	rebuilt, err := RebuildKeyGroups(tree, in.Config)
	if err != nil {
		return nil, err
	}
	tree.Metadata.KeyGroups = rebuilt

	ks := []keyservice.KeyServiceClient{keyservice.NewLocalClient()}
	dataKey, err := tree.Metadata.GetDataKeyWithKeyServices(ks, sops.DefaultDecryptionOrder)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: get data key for rotation: %w", err)
	}

	// Build the NEW master keys and re-encrypt the existing data key against them.
	newGroups, err := BuildMasterKeysFromRules(in.NewRules, in.Config)
	if err != nil {
		return nil, err
	}
	tree.Metadata.KeyGroups = newGroups
	tree.Metadata.LastModified = time.Now().UTC()

	// Encrypt-data-key step is what tree.Metadata.UpdateMasterKeys does in SOPS.
	encErrs := tree.Metadata.UpdateMasterKeysWithKeyServices(dataKey, ks)
	if len(encErrs) > 0 {
		return nil, fmt.Errorf("sopswrap: re-encrypt data key: %w", errors.Join(encErrs...))
	}

	out, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: emit rotated ciphertext: %w", err)
	}

	return &UpdateKeysResult{
		Ciphertext: out,
		Metadata:   ExtractMetadata(tree),
	}, nil
}
