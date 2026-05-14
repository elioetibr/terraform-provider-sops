package sopswrap_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

// setAgeEnv sets SOPS_AGE_KEY_FILE for the duration of the test.
// NOTE: t.Setenv is incompatible with t.Parallel() in Go 1.21+.
// Tests using this helper must NOT call t.Parallel().
func setAgeEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SOPS_AGE_KEY_FILE", absTestdata(t, "age-key.txt"))
}

func absTestdata(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// thisFile is .../internal/sopswrap/decrypt_test.go; testdata is at repo root
	return filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(thisFile))), "testdata", name)
}

func TestDecrypt_YAMLFixture(t *testing.T) {
	setAgeEnv(t)

	src, err := os.ReadFile(absTestdata(t, "secrets.yaml"))
	require.NoError(t, err)

	res, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: src,
		Format: sopswrap.FormatYAML,
		Config: auth.Config{},
	})
	require.NoError(t, err)
	require.Contains(t, string(res.Plaintext), "hunter2")
	require.Equal(t, "hunter2", res.Flat["database.password"])
	require.Equal(t, "sk-test-12345", res.Flat["api_key"])
}

func TestDecrypt_JSONFixture(t *testing.T) {
	setAgeEnv(t)
	src, err := os.ReadFile(absTestdata(t, "secrets.json"))
	require.NoError(t, err)
	res, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: src, Format: sopswrap.FormatJSON,
	})
	require.NoError(t, err)
	require.Contains(t, string(res.Plaintext), "hunter2")
}

func TestDecrypt_DotenvFixture(t *testing.T) {
	setAgeEnv(t)
	src, err := os.ReadFile(absTestdata(t, "secrets.env"))
	require.NoError(t, err)
	res, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: src, Format: sopswrap.FormatDotenv,
	})
	require.NoError(t, err)
	require.Equal(t, "hunter2", res.Flat["DATABASE_PASSWORD"])
}

func TestDecrypt_BinaryFixture(t *testing.T) {
	setAgeEnv(t)
	src, err := os.ReadFile(absTestdata(t, "secrets.bin"))
	require.NoError(t, err)
	res, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
		Source: src, Format: sopswrap.FormatBinary,
	})
	require.NoError(t, err)
	require.NotEmpty(t, res.Plaintext)
}

// Concurrency regression test — reproduces carlpett #126 if our semaphore is broken.
// Sets env directly (not via t.Setenv) so that t.Parallel() can be used.
func TestDecrypt_ParallelStable(t *testing.T) {
	// Set SOPS_AGE_KEY_FILE at process level so goroutines (and t.Parallel) work.
	// We restore the previous value when the test ends.
	keyFile := absTestdata(t, "age-key.txt")
	prev, hasPrev := os.LookupEnv("SOPS_AGE_KEY_FILE")
	require.NoError(t, os.Setenv("SOPS_AGE_KEY_FILE", keyFile))
	t.Cleanup(func() {
		if hasPrev {
			_ = os.Setenv("SOPS_AGE_KEY_FILE", prev)
		} else {
			_ = os.Unsetenv("SOPS_AGE_KEY_FILE")
		}
	})

	t.Parallel()

	src, err := os.ReadFile(absTestdata(t, "secrets.yaml"))
	require.NoError(t, err)

	const N = 32
	var wg sync.WaitGroup
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := sopswrap.Decrypt(context.Background(), sopswrap.DecryptInput{
				Source: src, Format: sopswrap.FormatYAML,
			})
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("parallel decrypt failed: %v", err)
	}
}
