package sopswrap

import (
	"context"
	"fmt"
	"sync"

	sops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/keyservice"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

// Package-level semaphore. Provider's Configure may swap it out.
var (
	semMu sync.RWMutex
	sem   = NewSemaphore(DefaultConcurrency)
)

// SetGlobalConcurrency replaces the package-level semaphore. Called by the
// provider's Configure with the user's `concurrency_limit`.
func SetGlobalConcurrency(limit int) {
	semMu.Lock()
	defer semMu.Unlock()
	sem = NewSemaphore(limit)
}

func getSem() *Semaphore {
	semMu.RLock()
	defer semMu.RUnlock()
	return sem
}

// DecryptInput is the request to Decrypt.
type DecryptInput struct {
	// Source is the raw encrypted bytes.
	Source []byte
	// Format selects the SOPS store. Required.
	Format Format
	// Config is the merged credential configuration for this call.
	Config auth.Config
	// IgnoreMAC, when true, skips MAC verification. Use only with a warning.
	IgnoreMAC bool
}

// Result is what Decrypt returns.
type Result struct {
	Plaintext []byte
	Flat      map[string]string
	JSON      []byte
	Metadata  Metadata
}

// Decrypt loads encrypted bytes, rebuilds master keys with injected credentials,
// fetches the data key via the local keyservice, decrypts the tree, and returns
// the multi-shape output.
func Decrypt(ctx context.Context, in DecryptInput) (*Result, error) {
	rel, err := getSem().Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: acquire semaphore: %w", err)
	}
	defer rel()

	// Scope SOPS env vars to this call (no global pollution).
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

	// THIS is the line that beats carlpett: we replace tree.Metadata.KeyGroups
	// with versions that carry our injected credentials.
	rebuilt, err := RebuildKeyGroups(tree, in.Config)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: rebuild key groups: %w", err)
	}
	tree.Metadata.KeyGroups = rebuilt

	ks := []keyservice.KeyServiceClient{keyservice.NewLocalClient()}
	dataKey, err := tree.Metadata.GetDataKeyWithKeyServices(ks, sops.DefaultDecryptionOrder)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: get data key: %w", err)
	}

	if _, err := tree.Decrypt(dataKey, aes.NewCipher()); err != nil {
		return nil, fmt.Errorf("sopswrap: decrypt tree: %w", err)
	}

	plaintext, err := store.EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: emit plain: %w", err)
	}

	js, err := ToJSON(tree.Branches)
	if err != nil {
		return nil, fmt.Errorf("sopswrap: to json: %w", err)
	}

	return &Result{
		Plaintext: plaintext,
		Flat:      Flatten(tree.Branches),
		JSON:      js,
		Metadata:  ExtractMetadata(tree),
	}, nil
}
