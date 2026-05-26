package sopswrap

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/provider/auth"
)

// TestApplyScopedEnv_RestoresBothBranches exercises both restoration paths:
//   - ok=true: SOPS_AGE_KEY had a prior value -> must be reset to it.
//   - ok=false: GNUPGHOME had no prior value -> must be unset.
//
// Can't t.Parallel — we mutate process-global env.
func TestApplyScopedEnv_RestoresBothBranches(t *testing.T) {
	// Branch 1 (ok=true): pre-set a value.
	t.Setenv("SOPS_AGE_KEY", "preexisting")

	// Branch 2 (ok=false): make sure GNUPGHOME is not set going in.
	// t.Setenv only handles setting; we need it absent. Snapshot + restore manually.
	if old, ok := os.LookupEnv("GNUPGHOME"); ok {
		require.NoError(t, os.Unsetenv("GNUPGHOME"))
		t.Cleanup(func() { _ = os.Setenv("GNUPGHOME", old) })
	} else {
		t.Cleanup(func() { _ = os.Unsetenv("GNUPGHOME") })
	}

	cfg := auth.Config{
		Age: auth.AgeConfig{Key: "scoped-age-key"},
		PGP: auth.PGPConfig{GnupgHome: "/tmp/gpg-scope-test"},
	}

	restore := applyScopedEnv(cfg)
	require.Equal(t, "scoped-age-key", os.Getenv("SOPS_AGE_KEY"))
	require.Equal(t, "/tmp/gpg-scope-test", os.Getenv("GNUPGHOME"))

	restore()
	require.Equal(t, "preexisting", os.Getenv("SOPS_AGE_KEY"), "ok=true branch must restore prior value")
	_, stillSet := os.LookupEnv("GNUPGHOME")
	require.False(t, stillSet, "ok=false branch must unset the key")
}

// TestApplyScopedEnv_EmptyConfigIsNoop confirms the early-return on v=="" is exercised.
func TestApplyScopedEnv_EmptyConfigIsNoop(t *testing.T) {
	restore := applyScopedEnv(auth.Config{})
	restore() // must not panic
}
