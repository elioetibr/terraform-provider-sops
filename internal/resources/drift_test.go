package resources

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestPlaintextDigest(t *testing.T) {
	t.Parallel()

	// Verify the output is a lowercase hex-encoded SHA-256 (64 chars).
	t.Run("length and format", func(t *testing.T) {
		t.Parallel()
		got := PlaintextDigest([]byte("test"))
		if len(got) != 64 {
			t.Errorf("PlaintextDigest length = %d; want 64", len(got))
		}
		for _, ch := range got {
			if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
				t.Errorf("PlaintextDigest contains non-hex char %q in %q", ch, got)
				break
			}
		}
	})

	// Verify determinism: same bytes → same digest.
	t.Run("deterministic", func(t *testing.T) {
		t.Parallel()
		input := []byte("some yaml:\n  key: value\n")
		if PlaintextDigest(input) != PlaintextDigest(input) {
			t.Error("PlaintextDigest is not deterministic")
		}
	})

	// Verify correctness against stdlib sha256.
	t.Run("matches stdlib sha256", func(t *testing.T) {
		t.Parallel()
		inputs := [][]byte{
			[]byte{},
			[]byte("hello world"),
			[]byte("abc"),
			[]byte("some yaml:\n  key: value\n"),
		}
		for _, in := range inputs {
			sum := sha256.Sum256(in)
			want := fmt.Sprintf("%x", sum)
			got := PlaintextDigest(in)
			if got != want {
				t.Errorf("PlaintextDigest(%q) = %q; want %q", in, got, want)
			}
		}
	})

	// Ensure different inputs produce different digests.
	t.Run("different inputs differ", func(t *testing.T) {
		t.Parallel()
		d1 := PlaintextDigest([]byte("foo"))
		d2 := PlaintextDigest([]byte("bar"))
		if d1 == d2 {
			t.Errorf("expected different digests for different inputs, got same: %q", d1)
		}
	})
}
