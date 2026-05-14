// Package resources implements the Terraform managed resources for the sops provider.
package resources

import (
	"crypto/sha256"
	"fmt"
)

// PlaintextDigest returns the lowercase hex-encoded SHA-256 digest of p.
// It is stored in state to detect out-of-band edits to the encrypted file:
// if the file is tampered with, decrypting it on Read will yield a different
// plaintext, and the digest will differ from the one stored in state.
func PlaintextDigest(p []byte) string {
	sum := sha256.Sum256(p)
	return fmt.Sprintf("%x", sum)
}
