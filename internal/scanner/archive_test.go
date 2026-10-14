package scanner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestScanRootFindsEICARInsideZipWithoutExtracting(t *testing.T) {
	root := t.TempDir()
	archivePath := filepath.Join(root, "bundle.zip")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	entry, err := zw.Create("../outside.txt")
	if err != nil { t.Fatal(err) }
	if _, err := entry.Write([]byte(EICARTestString)); err != nil { t.Fatal(err) }
	if err := zw.Close(); err != nil { t.Fatal(err) }
	if err := os.WriteFile(archivePath, buf.Bytes(), 0600); err != nil { t.Fatal(err) }

	result, err := ScanRoot(root, nil)
	if err != nil { t.Fatal(err) }
	found := false
	for _, f := range result.Findings {
		if f.FileType == "archive-member:zip" && f.Reason == "eicar-test-string" { found = true }
	}
	if !found { t.Fatalf("expected EICAR member finding; got %+v", result.Findings) }
	if _, err := os.Stat(filepath.Join(t.TempDir(), "outside.txt")); err == nil {
		t.Fatal("unexpected extracted file")
	}
}

func TestScanRootFindsHashInsideTar(t *testing.T) {
	root := t.TempDir()
	archivePath := filepath.Join(root, "bundle.tar")
	payload := []byte("known suspicious sample bytes")
	digest := sha256.Sum256(payload)
	denylist := map[string]struct{}{hex.EncodeToString(digest[:]): {}}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name:"sample.bin", Mode:0600, Size:int64(len(payload)), Typeflag:tar.TypeReg}); err != nil { t.Fatal(err) }
	if _, err := tw.Write(payload); err != nil { t.Fatal(err) }
	if err := tw.Close(); err != nil { t.Fatal(err) }
	if err := os.WriteFile(archivePath, buf.Bytes(), 0600); err != nil { t.Fatal(err) }
	result, err := ScanRoot(root, denylist)
	if err != nil { t.Fatal(err) }
	found := false
	for _, f := range result.Findings {
		if f.FileType == "archive-member:tar" && f.Reason == "sha256-denylist-match" { found = true }
	}
	if !found { t.Fatalf("expected denylist member finding; got %+v", result.Findings) }
}
