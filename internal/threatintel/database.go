// Package threatintel verifies and parses authenticated threat-intelligence snapshots.
// It does not download feeds or embed a production publisher key.
package threatintel

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	// MaxDatabaseBytes bounds the signed payload before parsing.
	MaxDatabaseBytes = 16 << 20
	// MaxEntries prevents unexpectedly large in-memory indexes.
	MaxEntries = 200_000
	maxFamilyBytes = 128
	maxSourceBytes = 128
)

var (
	ErrInvalidSignature = errors.New("threat-intelligence signature verification failed")
	ErrExpired          = errors.New("threat-intelligence database is expired or not yet valid")
	ErrRollback         = errors.New("threat-intelligence database version is below the minimum accepted version")
)

// Entry describes a known-bad file by its exact SHA-256 digest.
// Family and Source are display/provenance labels, not executable instructions.
type Entry struct {
	SHA256 string `json:"sha256"`
	Family string `json:"family"`
	Source string `json:"source"`
}

// Database is accepted only after the exact payload bytes pass Ed25519 verification.
type Database struct {
	Version    uint64
	GeneratedAt time.Time
	ExpiresAt   time.Time
	Entries     []Entry
	BySHA256    map[string]Entry
}

type wireDatabase struct {
	Version     uint64  `json:"version"`
	GeneratedAt string  `json:"generated_at"`
	ExpiresAt   string  `json:"expires_at"`
	Entries     []Entry `json:"entries"`
}

// VerifyAndLoad authenticates the exact JSON payload bytes with a trusted Ed25519
// public key, then validates schema, freshness, entries, and anti-rollback policy.
// signatureHex must be the detached, lowercase/uppercase-agnostic hex encoding of
// a 64-byte Ed25519 signature. The caller must obtain publicKey from a trusted,
// independently provisioned source; a key shipped beside an untrusted feed is not
// a trust anchor.
func VerifyAndLoad(payload []byte, signatureHex string, publicKey ed25519.PublicKey, minimumVersion uint64, now time.Time) (Database, error) {
	var empty Database
	if len(payload) == 0 || len(payload) > MaxDatabaseBytes {
		return empty, fmt.Errorf("database payload size must be between 1 byte and %d bytes", MaxDatabaseBytes)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return empty, errors.New("trusted Ed25519 public key has invalid length")
	}
	if len(signatureHex) != ed25519.SignatureSize*2 {
		return empty, errors.New("detached signature must be 128 hexadecimal characters")
	}
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return empty, errors.New("detached signature is not valid hexadecimal")
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return empty, ErrInvalidSignature
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire wireDatabase
	if err := decoder.Decode(&wire); err != nil {
		return empty, fmt.Errorf("decode signed database: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return empty, errors.New("database payload contains trailing JSON or data")
	}

	if wire.Version == 0 {
		return empty, errors.New("database version must be positive")
	}
	if wire.Version < minimumVersion {
		return empty, ErrRollback
	}
	if len(wire.Entries) > MaxEntries {
		return empty, fmt.Errorf("database has more than %d entries", MaxEntries)
	}
	generatedAt, err := parseUTC(wire.GeneratedAt)
	if err != nil {
		return empty, fmt.Errorf("invalid generated_at: %w", err)
	}
	expiresAt, err := parseUTC(wire.ExpiresAt)
	if err != nil {
		return empty, fmt.Errorf("invalid expires_at: %w", err)
	}
	if !expiresAt.After(generatedAt) {
		return empty, errors.New("expires_at must be later than generated_at")
	}
	if now.IsZero() {
		return empty, errors.New("current time is required")
	}
	now = now.UTC()
	if now.Before(generatedAt) || !now.Before(expiresAt) {
		return empty, ErrExpired
	}

	index := make(map[string]Entry, len(wire.Entries))
	for i, entry := range wire.Entries {
		if len(entry.SHA256) != 64 || entry.SHA256 != strings.ToLower(entry.SHA256) {
			return empty, fmt.Errorf("entry %d has a non-canonical SHA-256 digest", i)
		}
		rawDigest, err := hex.DecodeString(entry.SHA256)
		if err != nil || len(rawDigest) != 32 {
			return empty, fmt.Errorf("entry %d has an invalid SHA-256 digest", i)
		}
		if entry.Family == "" || len(entry.Family) > maxFamilyBytes || strings.TrimSpace(entry.Family) != entry.Family {
			return empty, fmt.Errorf("entry %d has an invalid family label", i)
		}
		if entry.Source == "" || len(entry.Source) > maxSourceBytes || strings.TrimSpace(entry.Source) != entry.Source {
			return empty, fmt.Errorf("entry %d has an invalid source label", i)
		}
		if _, exists := index[entry.SHA256]; exists {
			return empty, fmt.Errorf("entry %d duplicates a SHA-256 digest", i)
		}
		index[entry.SHA256] = entry
	}

	return Database{
		Version: wire.Version, GeneratedAt: generatedAt, ExpiresAt: expiresAt,
		Entries: wire.Entries, BySHA256: index,
	}, nil
}

func parseUTC(value string) (time.Time, error) {
	if value == "" || !strings.HasSuffix(value, "Z") {
		return time.Time{}, errors.New("timestamp must be RFC3339 UTC ending in Z")
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}
