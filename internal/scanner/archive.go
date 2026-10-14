package scanner

import (
	"archive/tar"
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	maxArchiveEntries      = 4096
	maxArchiveEntryBytes   = int64(64 << 20)
	maxArchiveExpandedSize = int64(256 << 20)
)

// inspectArchiveEntries only reads archive members; it never extracts them to disk.
// Limits bound member count and decompressed bytes. Unsupported archive formats are
// left as outer-file-only scans, not reported as fully inspected.
func inspectArchiveEntries(f *os.File, size int64, fileType, outerPath string, denylist map[string]struct{}) ([]Finding, []error) {
	switch fileType {
	case "archive:zip":
		return inspectZip(f, size, outerPath, denylist)
	case "archive:tar":
		return inspectTar(f, outerPath, denylist)
	default:
		return nil, nil
	}
}

func inspectZip(f *os.File, size int64, outerPath string, denylist map[string]struct{}) ([]Finding, []error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, []error{err}
	}
	zr, err := zip.NewReader(f, size)
	if err != nil {
		return nil, []error{fmt.Errorf("invalid ZIP structure: %w", err)}
	}
	if len(zr.File) > maxArchiveEntries {
		return nil, []error{fmt.Errorf("ZIP member count exceeds limit (%d)", maxArchiveEntries)}
	}
	findings := []Finding{}
	errs := []error{}
	var total int64
	for _, entry := range zr.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		if entry.UncompressedSize64 > uint64(maxArchiveEntryBytes) {
			errs = append(errs, fmt.Errorf("%q exceeds per-entry expansion limit", entry.Name))
			continue
		}
		if entry.UncompressedSize64 > uint64(maxArchiveExpandedSize-total) {
			errs = append(errs, errors.New("ZIP expanded-size limit exceeded"))
			break
		}
		total += int64(entry.UncompressedSize64)
		rc, err := entry.Open()
		if err != nil {
			errs = append(errs, fmt.Errorf("%q: open failed: %w", entry.Name, err))
			continue
		}
		hash, eicar, readErr := hashAndFind(io.LimitReader(rc, maxArchiveEntryBytes+1))
		closeErr := rc.Close()
		if readErr != nil || closeErr != nil {
			cause := readErr
			if cause == nil { cause = closeErr }
			errs = append(errs, fmt.Errorf("%q: read failed: %w", entry.Name, cause))
			continue
		}
		reason := detectionReason(hash, eicar, denylist)
		if reason != "" {
			findings = append(findings, Finding{
				Path: outerPath + "!" + safeMemberLabel(entry.Name),
				SHA256: hash, FileType: "archive-member:zip", Reason: reason,
			})
		}
	}
	return findings, errs
}

func inspectTar(f *os.File, outerPath string, denylist map[string]struct{}) ([]Finding, []error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, []error{err}
	}
	tr := tar.NewReader(f)
	findings := []Finding{}
	errs := []error{}
	var total int64
	entries := 0
	for {
		header, err := tr.Next()
		if err == io.EOF { break }
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid TAR structure: %w", err))
			break
		}
		entries++
		if entries > maxArchiveEntries {
			errs = append(errs, fmt.Errorf("TAR member count exceeds limit (%d)", maxArchiveEntries))
			break
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}
		if header.Size < 0 || header.Size > maxArchiveEntryBytes {
			errs = append(errs, fmt.Errorf("%q exceeds per-entry expansion limit", header.Name))
			break
		}
		if header.Size > maxArchiveExpandedSize-total {
			errs = append(errs, errors.New("TAR expanded-size limit exceeded"))
			break
		}
		total += header.Size
		hash, eicar, readErr := hashAndFind(io.LimitReader(tr, header.Size))
		if readErr != nil {
			errs = append(errs, fmt.Errorf("%q: read failed: %w", header.Name, readErr))
			break
		}
		reason := detectionReason(hash, eicar, denylist)
		if reason != "" {
			findings = append(findings, Finding{
				Path: outerPath + "!" + safeMemberLabel(header.Name),
				SHA256: hash, FileType: "archive-member:tar", Reason: reason,
			})
		}
	}
	return findings, errs
}

func detectionReason(hash string, eicar bool, denylist map[string]struct{}) string {
	reason := ""
	if _, matched := denylist[hash]; matched { reason = "sha256-denylist-match" }
	if eicar {
		if reason != "" { reason += ",eicar-test-string" } else { reason = "eicar-test-string" }
	}
	return reason
}

func safeMemberLabel(name string) string {
	// Display only; this label is never used as a filesystem path.
	name = strings.ReplaceAll(name, "\\", "/")
	return strings.TrimLeft(name, "/")
}
