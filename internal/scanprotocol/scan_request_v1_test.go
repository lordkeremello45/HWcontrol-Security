package scanprotocol

import (
	"encoding/json"
	"os"
	"testing"
)

type vector struct {
	Secret string `json:"secret"`
	Request Request `json:"request"`
	CanonicalPayload string `json:"canonical_payload"`
}

func loadVector(t *testing.T) vector {
	t.Helper()
	data, err := os.ReadFile("testdata/scan_request_v1.json")
	if err != nil { t.Fatal(err) }
	var v vector
	if err := json.Unmarshal(data, &v); err != nil { t.Fatal(err) }
	return v
}

func TestSharedVectorCanonicalPayloadAndHMAC(t *testing.T) {
	v := loadVector(t)
	payload, err := CanonicalPayload(v.Request)
	if err != nil { t.Fatal(err) }
	if payload != v.CanonicalPayload { t.Fatalf("canonical payload mismatch: %q", payload) }
	if err := Verify(v.Request, []byte(v.Secret)); err != nil { t.Fatalf("shared HMAC vector rejected: %v", err) }
	got, err := Sign(v.Request, []byte(v.Secret))
	if err != nil { t.Fatal(err) }
	if got != v.Request.Auth { t.Fatalf("signature = %s, want %s", got, v.Request.Auth) }
}

func TestEverySignedFieldIsBound(t *testing.T) {
	v := loadVector(t)
	mutations := []func(*Request){
		func(r *Request) { r.ScopeID = "system-root" },
		func(r *Request) { r.Mode = "read_write" },
		func(r *Request) { r.TimestampMS++ },
		func(r *Request) { r.Nonce = "1123456789abcdef0123456789abcdef" },
		func(r *Request) { r.RequestID = "request-0002" },
	}
	for i, mutate := range mutations {
		r := v.Request
		mutate(&r)
		if err := Verify(r, []byte(v.Secret)); err == nil { t.Errorf("mutation %d unexpectedly verified", i) }
	}
}

func TestRejectsMalformedFieldsAndEmptyKey(t *testing.T) {
	v := loadVector(t)
	cases := []struct{name string; mutate func(*Request)}{
		{"newline scope", func(r *Request) { r.ScopeID = "user-home\nother" }},
		{"unknown mode", func(r *Request) { r.Mode = "scan-and-delete" }},
		{"bad nonce", func(r *Request) { r.Nonce = "short" }},
		{"bad request id", func(r *Request) { r.RequestID = "id with spaces" }},
		{"bad timestamp", func(r *Request) { r.TimestampMS = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { r := v.Request; tc.mutate(&r); if _, err := CanonicalPayload(r); err == nil { t.Fatal("expected invalid field to be rejected") } })
	}
	if _, err := Sign(v.Request, nil); err == nil { t.Fatal("empty key must be rejected") }
}
