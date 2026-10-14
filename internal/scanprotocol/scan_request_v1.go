// Package scanprotocol defines the versioned, authenticated request envelope for a
// future read-only security scan. It is deliberately not wired into the live Bridge.
package scanprotocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const Version = "HWSECURITY-SCAN-V1"

var (
	scopePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	noncePattern = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	requestPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// Request contains only scan-specific fields. Timestamp is Unix milliseconds.
// Auth is excluded from the canonical payload and is a lowercase hex HMAC-SHA-256.
type Request struct {
	Action      string `json:"action"`
	ScopeID     string `json:"scope_id"`
	Mode        string `json:"mode"`
	TimestampMS int64  `json:"timestamp_ms"`
	Nonce       string `json:"nonce"`
	RequestID   string `json:"request_id"`
	Auth        string `json:"auth"`
}

// CanonicalPayload binds every security-relevant field in a versioned, newline-delimited encoding.
// The field grammar rejects newlines and separators by construction.
func CanonicalPayload(r Request) (string, error) {
	if r.Action != "scan" {
		return "", errors.New("unsupported scan action")
	}
	if !scopePattern.MatchString(r.ScopeID) {
		return "", errors.New("invalid scope_id")
	}
	if r.Mode != "read_only" {
		return "", errors.New("unsupported scan mode")
	}
	if r.TimestampMS <= 0 {
		return "", errors.New("timestamp_ms must be positive")
	}
	if !noncePattern.MatchString(r.Nonce) {
		return "", errors.New("nonce must be 32 hexadecimal characters")
	}
	if !requestPattern.MatchString(r.RequestID) {
		return "", errors.New("invalid request_id")
	}
	fields := []string{
		Version,
		r.Action,
		r.ScopeID,
		r.Mode,
		strconv.FormatInt(r.TimestampMS, 10),
		strings.ToLower(r.Nonce),
		r.RequestID,
	}
	return strings.Join(fields, "\n"), nil
}

func Sign(r Request, secret []byte) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("empty authentication key")
	}
	payload, err := CanonicalPayload(r)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func Verify(r Request, secret []byte) error {
	if len(secret) == 0 {
		return errors.New("empty authentication key")
	}
	provided, err := hex.DecodeString(r.Auth)
	if err != nil || len(provided) != sha256.Size {
		return errors.New("invalid authentication tag")
	}
	expected, err := Sign(r, secret)
	if err != nil {
		return err
	}
	expectedBytes, _ := hex.DecodeString(expected)
	if !hmac.Equal(provided, expectedBytes) {
		return fmt.Errorf("authentication failed")
	}
	return nil
}
