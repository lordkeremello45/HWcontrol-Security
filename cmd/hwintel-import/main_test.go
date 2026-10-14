package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lordkeremello45/HWcontrol-Security/internal/malwarebazaar"
)

func tempStream(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stream-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func readStream(t *testing.T, f *os.File) string {
	t.Helper()
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func testNow() time.Time { return time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC) }

func TestRunWithFetchWritesUnsignedCandidateSafely(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "candidate.json")
	stdout, stderr := tempStream(t), tempStream(t)
	calls := 0
	fetch := func(ctx context.Context, hours int) ([]malwarebazaar.Entry, error) {
		calls++
		if hours != 24 {
			t.Fatalf("hours = %d, want 24", hours)
		}
		return []malwarebazaar.Entry{{SHA256: strings.Repeat("a", 64), Family: "Example", Source: "MalwareBazaar"}}, nil
	}
	code := runWithFetch([]string{"-hours", "24", "-version", "7", "-out", outPath},
		func(k string) string { if k == "MALWAREBAZAAR_AUTH_KEY" { return "test-key" }; return "" },
		testNow, stdout, stderr, fetch)
	if code != 0 || calls != 1 {
		t.Fatalf("code=%d calls=%d stderr=%s", code, calls, readStream(t, stderr))
	}
	payload, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var got candidate
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != 7 || got.GeneratedAt != "2026-10-14T12:00:00Z" ||
		got.ExpiresAt != "2026-10-21T12:00:00Z" || len(got.Entries) != 1 {
		t.Fatalf("unexpected candidate: %#v", got)
	}
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("candidate permissions = %o, want 600", info.Mode().Perm())
	}
	if !strings.Contains(readStream(t, stdout), "UNSIGNED") {
		t.Fatal("success output must clearly label the candidate unsigned")
	}
}

func TestRunWithFetchRejectsMissingKeyBeforeNetwork(t *testing.T) {
	stdout, stderr := tempStream(t), tempStream(t)
	called := false
	code := runWithFetch([]string{"-out", filepath.Join(t.TempDir(), "candidate.json")},
		func(string) string { return "" }, testNow, stdout, stderr,
		func(context.Context, int) ([]malwarebazaar.Entry, error) {
			called = true
			return nil, nil
		})
	if code != 2 || called {
		t.Fatalf("code=%d called=%v; missing key must fail before fetching", code, called)
	}
}

func TestRunWithFetchRejectsEmptyResultsAndPreservesExistingOutput(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "candidate.json")
	if err := os.WriteFile(outPath, []byte("keep-me"), 0600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr := tempStream(t), tempStream(t)
	code := runWithFetch([]string{"-out", outPath},
		func(string) string { return "test-key" }, testNow, stdout, stderr,
		func(context.Context, int) ([]malwarebazaar.Entry, error) { return nil, nil })
	if code != 1 {
		t.Fatalf("empty result code = %d, want 1", code)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep-me" {
		t.Fatalf("existing candidate changed: %q", data)
	}
	if !strings.Contains(readStream(t, stderr), "no family-labelled detections") {
		t.Fatal("expected explicit empty-feed error")
	}
}

func TestRunWithFetchRejectsExistingOutputAndFetchError(t *testing.T) {
	t.Run("existing output", func(t *testing.T) {
		outPath := filepath.Join(t.TempDir(), "candidate.json")
		if err := os.WriteFile(outPath, []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
		stdout, stderr := tempStream(t), tempStream(t)
		code := runWithFetch([]string{"-out", outPath}, func(string) string { return "key" },
			testNow, stdout, stderr, func(context.Context, int) ([]malwarebazaar.Entry, error) {
				return []malwarebazaar.Entry{{SHA256: strings.Repeat("b", 64), Family: "Example", Source: "MalwareBazaar"}}, nil
			})
		if code != 1 || !strings.Contains(readStream(t, stderr), "refusing to overwrite") {
			t.Fatalf("code=%d stderr=%s", code, readStream(t, stderr))
		}
	})
	t.Run("fetch error", func(t *testing.T) {
		stdout, stderr := tempStream(t), tempStream(t)
		code := runWithFetch([]string{"-out", filepath.Join(t.TempDir(), "candidate.json")},
			func(string) string { return "key" }, testNow, stdout, stderr,
			func(context.Context, int) ([]malwarebazaar.Entry, error) { return nil, errors.New("offline") })
		if code != 1 || !strings.Contains(readStream(t, stderr), "import failed") {
			t.Fatalf("code=%d stderr=%s", code, readStream(t, stderr))
		}
	})
}

func TestRunWithFetchRejectsInvalidArguments(t *testing.T) {
	stdout, stderr := tempStream(t), tempStream(t)
	called := false
	code := runWithFetch([]string{"-version", "0"}, func(string) string { return "key" },
		testNow, stdout, stderr, func(context.Context, int) ([]malwarebazaar.Entry, error) {
			called = true
			return nil, nil
		})
	if code != 2 || called {
		t.Fatalf("code=%d called=%v; invalid version must fail before fetching", code, called)
	}
}
