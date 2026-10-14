package scanner

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	// MaxHashListBytes prevents unbounded memory use from an untrusted local list.
	MaxHashListBytes = 4 << 20
	maxLineBytes     = 256
)

// EICARTestString is the standard antivirus test string. It is harmless test data,
// not malware. Detection only reports a finding; it never executes or removes files.
const EICARTestString = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

type Finding struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Reason string `json:"reason"`
}

type Result struct {
	FilesScanned int       `json:"files_scanned"`
	Findings     []Finding `json:"findings"`
	Errors       []string  `json:"errors,omitempty"`
}

func LoadSHA256List(path string) (map[string]struct{}, error) {
	out := make(map[string]struct{})
	if path == "" {
		return out, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open hash list: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat hash list: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > MaxHashListBytes {
		return nil, errors.New("hash list must be a regular file no larger than 4 MiB")
	}

	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1024), maxLineBytes)
	for line := 1; s.Scan(); line++ {
		value := strings.TrimSpace(s.Text())
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		if len(value) != sha256.Size*2 {
			return nil, fmt.Errorf("invalid SHA-256 entry at line %d", line)
		}
		raw, err := hex.DecodeString(value)
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("invalid SHA-256 entry at line %d", line)
		}
		out[strings.ToLower(value)] = struct{}{}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("read hash list: %w", err)
	}
	return out, nil
}

// ScanRoot scans regular files under root without following symlinks or modifying
// any files. Errors are returned in the result so a partial scan cannot be mistaken
// for a clean scan. The caller must treat any error as an incomplete result.
func ScanRoot(root string, denylist map[string]struct{}) (Result, error) {
	result := Result{Findings: []Finding{}, Errors: []string{}}
	if strings.TrimSpace(root) == "" {
		return result, errors.New("scan root is required")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return result, fmt.Errorf("inspect scan root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return result, errors.New("scan root must be a real directory, not a symlink")
	}

	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", path, walkErr))
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			// Do not follow symlinks; report them so the caller knows the scan was bounded.
			result.Errors = append(result.Errors, fmt.Sprintf("%s: symlink skipped", path))
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: non-regular file skipped", path))
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: open failed: %v", path, err))
			return nil
		}
		info, statErr := f.Stat()
		if statErr != nil || !info.Mode().IsRegular() {
			_ = f.Close()
			result.Errors = append(result.Errors, fmt.Sprintf("%s: file changed or is not regular", path))
			return nil
		}

		hash, eicarFound, readErr := hashAndFind(f)
		closeErr := f.Close()
		if readErr != nil || closeErr != nil {
			cause := readErr
			if cause == nil {
				cause = closeErr
			}
			result.Errors = append(result.Errors, fmt.Sprintf("%s: read failed: %v", path, cause))
			return nil
		}
		result.FilesScanned++
		reason := ""
		if _, matched := denylist[hash]; matched {
			reason = "sha256-denylist-match"
		}
		if eicarFound {
			if reason != "" {
				reason += ",eicar-test-string"
			} else {
				reason = "eicar-test-string"
			}
		}
		if reason != "" {
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			result.Findings = append(result.Findings, Finding{Path: rel, SHA256: hash, Reason: reason})
		}
		return nil
	})
	if err != nil {
		return result, fmt.Errorf("walk scan root: %w", err)
	}
	return result, nil
}

func hashAndFind(r io.Reader) (string, bool, error) {
	h := sha256.New()
	needle := []byte(EICARTestString)
	const chunkSize = 32 * 1024
	buf := make([]byte, chunkSize)
	var tail []byte
	found := false

	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			_, _ = h.Write(chunk)
			if !found {
				window := make([]byte, 0, len(tail)+len(chunk))
				window = append(window, tail...)
				window = append(window, chunk...)
				if contains(window, needle) {
					found = true
				}
				keep := len(needle) - 1
				if len(window) > keep {
					tail = append(tail[:0], window[len(window)-keep:]...)
				} else {
					tail = append(tail[:0], window...)
				}
			}
		}
		if err == io.EOF {
			return hex.EncodeToString(h.Sum(nil)), found, nil
		}
		if err != nil {
			return "", false, err
		}
	}
}

func contains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
