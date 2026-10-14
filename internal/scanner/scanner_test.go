package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanRootFindsEICARAndHashMatch(t *testing.T) {
	root := t.TempDir()
	payload := []byte("prefix-" + EICARTestString + "-suffix")
	path := filepath.Join(root, "sample.bin")
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	denylist := map[string]struct{}{hex.EncodeToString(digest[:]): {}}

	result, err := ScanRoot(root, denylist)
	if err != nil {
		t.Fatal(err)
	}
	if result.FilesScanned != 1 {
		t.Fatalf("FilesScanned = %d, want 1", result.FilesScanned)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Findings))
	}
	if !strings.Contains(result.Findings[0].Reason, "sha256-denylist-match") ||
		!strings.Contains(result.Findings[0].Reason, "eicar-test-string") {
		t.Fatalf("unexpected reason: %q", result.Findings[0].Reason)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatal("scanner modified scanned file")
	}
}

func TestHashAndFindAcrossChunkBoundary(t *testing.T) {
	payload := strings.Repeat("a", 32*1024-8) + EICARTestString
	_, found, err := hashAndFind(strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("EICAR string split across read boundary was not detected")
	}
}

func TestLoadSHA256ListRejectsMalformedEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hashes.txt")
	if err := os.WriteFile(path, []byte("not-a-hash\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSHA256List(path); err == nil {
		t.Fatal("expected malformed hash list to be rejected")
	}
}

func TestScanRootRejectsSymlinkRoot(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := ScanRoot(link, nil); err == nil {
		t.Fatal("expected symlink root to be rejected")
	}
}

func TestScanRootSkipsSymlinkedFile(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "outside.bin")
	if err := os.WriteFile(target, []byte(EICARTestString), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked.bin")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	result, err := ScanRoot(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.FilesScanned != 0 {
		t.Fatalf("FilesScanned = %d, want 0", result.FilesScanned)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("findings = %d, want 0 for a skipped symlink", len(result.Findings))
	}
	if len(result.Errors) == 0 {
		t.Fatal("expected skipped symlink to make the scan incomplete")
	}
}

func TestLoadSHA256ListRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hashes.txt")
	content := strings.Repeat("a", MaxHashListBytes+1)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSHA256List(path); err == nil {
		t.Fatal("expected oversized hash list to be rejected")
	}
}
