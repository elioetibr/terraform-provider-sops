// Package sopswrap is the thin wrapper around the SOPS Go library that lets us
// inject per-call credentials. Callers should never import sops/v3 directly.
package sopswrap

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/stores/dotenv"
	"github.com/getsops/sops/v3/stores/ini"
	"github.com/getsops/sops/v3/stores/json"
	"github.com/getsops/sops/v3/stores/yaml"
)

// Format names the SOPS plaintext/ciphertext format.
type Format string

const (
	FormatYAML   Format = "yaml"
	FormatJSON   Format = "json"
	FormatDotenv Format = "dotenv"
	FormatINI    Format = "ini"
	FormatBinary Format = "binary"
	FormatRaw    Format = "raw" // alias for Binary at the API layer
)

// Store unifies the SOPS Store interface (load encrypted/plaintext file, emit either).
type Store interface {
	LoadEncryptedFile(in []byte) (sops.Tree, error)
	LoadPlainFile(in []byte) (sops.TreeBranches, error)
	EmitEncryptedFile(tree sops.Tree) ([]byte, error)
	EmitPlainFile(tree sops.TreeBranches) ([]byte, error)
}

// StoreFor returns the SOPS Store for the given format.
func StoreFor(f Format) (Store, error) {
	switch f {
	case FormatYAML:
		return &yaml.Store{}, nil
	case FormatJSON:
		return &json.Store{}, nil
	case FormatDotenv:
		return &dotenv.Store{}, nil
	case FormatINI:
		return &ini.Store{}, nil
	case FormatBinary, FormatRaw:
		return &json.BinaryStore{}, nil
	default:
		return nil, fmt.Errorf("sopswrap: unknown format %q (want yaml|json|dotenv|ini|binary|raw)", f)
	}
}

// FormatFromPath auto-detects from file extension. Falls back to FormatBinary
// (matches SOPS CLI behavior for unrecognized extensions).
func FormatFromPath(p string) Format {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".yaml", ".yml":
		return FormatYAML
	case ".json":
		return FormatJSON
	case ".env":
		return FormatDotenv
	case ".ini":
		return FormatINI
	default:
		return FormatBinary
	}
}
