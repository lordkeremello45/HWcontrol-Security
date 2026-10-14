package threatintel

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

const validPayload = `{"version":2,"generated_at":"2026-10-14T00:00:00Z","expires_at":"2026-10-21T00:00:00Z","entries":[{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","family":"test-family","source":"test-feed"}]}`

func signedFixture(t *testing.T, payload string) (ed25519.PublicKey, string) {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, []byte(payload))
	return pub, hex.EncodeToString(signature)
}

func TestVerifyAndLoadAcceptsValidSignedDatabase(t *testing.T) {
	pub, signature := signedFixture(t, validPayload)
	db, err := VerifyAndLoad([]byte(validPayload), signature, pub, 2, time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if db.Version != 2 || len(db.Entries) != 1 {
		t.Fatalf("unexpected database: version=%d entries=%d", db.Version, len(db.Entries))
	}
	if _, ok := db.BySHA256[strings.Repeat("a", 64)]; !ok {
		t.Fatal("expected validated digest index entry")
	}
}

func TestVerifyAndLoadRejectsTamperedPayload(t *testing.T) {
	pub, signature := signedFixture(t, validPayload)
	tampered := strings.Replace(validPayload, "test-family", "other-family", 1)
	_, err := VerifyAndLoad([]byte(tampered), signature, pub, 1, time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC))
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("error = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyAndLoadRejectsWrongKey(t *testing.T) {
	_, signature := signedFixture(t, validPayload)
	otherPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyAndLoad([]byte(validPayload), signature, otherPublicKey, 1, time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC))
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("error = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyAndLoadRejectsRollback(t *testing.T) {
	pub, signature := signedFixture(t, validPayload)
	_, err := VerifyAndLoad([]byte(validPayload), signature, pub, 3, time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC))
	if !errors.Is(err, ErrRollback) {
		t.Fatalf("error = %v, want ErrRollback", err)
	}
}

func TestVerifyAndLoadRejectsExpiredAndFutureDatabase(t *testing.T) {
	pub, signature := signedFixture(t, validPayload)
	for _, now := range []time.Time{
		time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 10, 13, 23, 59, 0, 0, time.UTC),
	} {
		if _, err := VerifyAndLoad([]byte(validPayload), signature, pub, 1, now); !errors.Is(err, ErrExpired) {
			t.Fatalf("time %s: error = %v, want ErrExpired", now, err)
		}
	}
}

func TestVerifyAndLoadRejectsMalformedEntriesAndUnknownFields(t *testing.T) {
	cases := []string{
		`{"version":2,"generated_at":"2026-10-14T00:00:00Z","expires_at":"2026-10-21T00:00:00Z","entries":[{"sha256":"ABC","family":"x","source":"y"}]}`,
		`{"version":2,"generated_at":"2026-10-14T00:00:00Z","expires_at":"2026-10-21T00:00:00Z","entries":[{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","family":"x","source":"y"},{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","family":"x","source":"y"}]}`,
		`{"version":2,"generated_at":"2026-10-14T00:00:00Z","expires_at":"2026-10-21T00:00:00Z","entries":[],"untrusted":"field"}`,
		`{"version":2,"generated_at":"2026-10-14T00:00:00+00:00","expires_at":"2026-10-21T00:00:00Z","entries":[]}`,
	}
	for _, payload := range cases {
		pub, signature := signedFixture(t, payload)
		if _, err := VerifyAndLoad([]byte(payload), signature, pub, 1, time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)); err == nil {
			t.Fatalf("expected payload rejection: %s", payload)
		}
	}
}

func TestVerifyAndLoadRejectsTrailingDataAndBadSignatureEncoding(t *testing.T) {
	payload := validPayload + " {}"
	pub, signature := signedFixture(t, payload)
	if _, err := VerifyAndLoad([]byte(payload), signature, pub, 1, time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected trailing data rejection")
	}
	if _, err := VerifyAndLoad([]byte(validPayload), "not-a-signature", pub, 1, time.Now().UTC()); err == nil {
		t.Fatal("expected malformed signature rejection")
	}
}

func TestVerifyAndLoadRejectsEmptyOrOversizedPayloadAndInvalidKey(t *testing.T) {
	pub, signature := signedFixture(t, validPayload)
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	if _, err := VerifyAndLoad(nil, signature, pub, 1, now); err == nil {
		t.Fatal("expected empty payload rejection")
	}
	if _, err := VerifyAndLoad(make([]byte, MaxDatabaseBytes+1), signature, pub, 1, now); err == nil {
		t.Fatal("expected oversized payload rejection")
	}
	if _, err := VerifyAndLoad([]byte(validPayload), signature, pub[:8], 1, now); err == nil {
		t.Fatal("expected invalid public key rejection")
	}
}
