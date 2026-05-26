package sopswrap

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	sops "github.com/getsops/sops/v3"
)

// Flatten produces the carlpett-compatible flat map[string]string output.
// Nested keys are joined with ".". List indices are stringified.
func Flatten(branches sops.TreeBranches) map[string]string {
	out := map[string]string{}
	for _, branch := range branches {
		walk(out, "", branch)
	}
	return out
}

func walk(out map[string]string, prefix string, v interface{}) {
	switch tv := v.(type) {
	case sops.TreeBranch:
		for _, item := range tv {
			keyStr := fmt.Sprintf("%v", item.Key)
			next := keyStr
			if prefix != "" {
				next = prefix + "." + keyStr
			}
			walk(out, next, item.Value)
		}
	case []interface{}:
		for i, item := range tv {
			next := strconv.Itoa(i)
			if prefix != "" {
				next = prefix + "." + next
			}
			walk(out, next, item)
		}
	case sops.Comment:
		// Skip SOPS-internal comments.
	default:
		out[prefix] = fmt.Sprintf("%v", tv)
	}
}

// ToJSON marshals the decrypted tree into structured JSON (spec §6.1 data_json).
func ToJSON(branches sops.TreeBranches) ([]byte, error) {
	obj := toGo(branches)
	return json.Marshal(obj)
}

func toGo(v interface{}) interface{} {
	switch tv := v.(type) {
	case sops.TreeBranches:
		// Multiple branches (rare; YAML multi-doc). Return as list.
		if len(tv) == 1 {
			return toGo(tv[0])
		}
		out := make([]interface{}, len(tv))
		for i, b := range tv {
			out[i] = toGo(b)
		}
		return out
	case sops.TreeBranch:
		m := map[string]interface{}{}
		for _, item := range tv {
			if _, ok := item.Key.(sops.Comment); ok {
				continue
			}
			m[fmt.Sprintf("%v", item.Key)] = toGo(item.Value)
		}
		return m
	case []interface{}:
		out := make([]interface{}, 0, len(tv))
		for _, item := range tv {
			if _, ok := item.(sops.Comment); ok {
				continue
			}
			out = append(out, toGo(item))
		}
		return out
	case sops.Comment:
		return nil
	default:
		return v
	}
}

// Metadata is the surface we expose as the `metadata` attribute on data sources.
type Metadata struct {
	LastModified      time.Time `json:"lastmodified"`
	MAC               string    `json:"mac"`
	Version           string    `json:"version"`
	KMSARNs           []string  `json:"kms_arns"`
	GCPKMSResources   []string  `json:"gcp_kms_resources"`
	AzureKVURLs       []string  `json:"azure_kv_urls"`
	AgeRecipients     []string  `json:"age_recipients"`
	PGPFingerprints   []string  `json:"pgp_fingerprints"`
	UnencryptedSuffix string    `json:"unencrypted_suffix,omitempty"`
	EncryptedSuffix   string    `json:"encrypted_suffix,omitempty"`
	UnencryptedRegex  string    `json:"unencrypted_regex,omitempty"`
	EncryptedRegex    string    `json:"encrypted_regex,omitempty"`
}

// ExtractMetadata pulls audit-relevant metadata out of a tree.
// Tolerates partial/empty key groups (e.g., in tests).
func ExtractMetadata(tree sops.Tree) Metadata {
	meta := Metadata{
		LastModified:      tree.Metadata.LastModified,
		MAC:               tree.Metadata.MessageAuthenticationCode,
		Version:           tree.Metadata.Version,
		UnencryptedSuffix: tree.Metadata.UnencryptedSuffix,
		EncryptedSuffix:   tree.Metadata.EncryptedSuffix,
		UnencryptedRegex:  tree.Metadata.UnencryptedRegex,
		EncryptedRegex:    tree.Metadata.EncryptedRegex,
	}
	for _, group := range tree.Metadata.KeyGroups {
		for _, k := range group {
			typeName := strings.ToLower(fmt.Sprintf("%T", k))
			// Order matters: "gcpkms.masterkey" must be checked before
			// "kms.masterkey" because the latter is a substring of the former.
			switch {
			case strings.Contains(typeName, "gcpkms.masterkey"):
				meta.GCPKMSResources = append(meta.GCPKMSResources, k.ToString())
			case strings.Contains(typeName, "azkv.masterkey"):
				meta.AzureKVURLs = append(meta.AzureKVURLs, k.ToString())
			case strings.Contains(typeName, "age.masterkey"):
				meta.AgeRecipients = append(meta.AgeRecipients, k.ToString())
			case strings.Contains(typeName, "pgp.masterkey"):
				meta.PGPFingerprints = append(meta.PGPFingerprints, k.ToString())
			case strings.Contains(typeName, "kms.masterkey"):
				meta.KMSARNs = append(meta.KMSARNs, k.ToString())
			}
		}
	}
	return meta
}
