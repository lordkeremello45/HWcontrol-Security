// hwintel-import downloads hash metadata only and emits an UNSIGNED candidate
// snapshot. It never downloads or executes malware samples.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lordkeremello45/HWcontrol-Security/internal/malwarebazaar"
)

type candidate struct {
	Version     uint64                  `json:"version"`
	GeneratedAt string                  `json:"generated_at"`
	ExpiresAt   string                  `json:"expires_at"`
	Entries     []malwarebazaar.Entry   `json:"entries"`
}

func run(args []string, getenv func(string) string, now func() time.Time, stdout, stderr *os.File) int {
	flags := flag.NewFlagSet("hwintel-import", flag.ContinueOnError)
	flags.SetOutput(stderr)
	hours := flags.Int("hours", 48, "lookback window in hours (1-168)")
	outPath := flags.String("out", "threat-intel-candidate.json", "output path for the unsigned candidate")
	version := flags.Uint64("version", 1, "candidate database version")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *version == 0 {
		fmt.Fprintln(stderr, "invalid arguments: version must be positive and no positional arguments are accepted")
		return 2
	}
	if strings.TrimSpace(*outPath) == "" || *outPath == "-" {
		fmt.Fprintln(stderr, "output must be a named file; stdout output is disabled to reduce accidental disclosure")
		return 2
	}
	key := getenv("MALWAREBAZAAR_AUTH_KEY")
	if strings.TrimSpace(key) == "" {
		fmt.Fprintln(stderr, "MALWAREBAZAAR_AUTH_KEY is required; configure it in local secret storage")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	entries, err := (malwarebazaar.Client{AuthKey: key}).FetchRecent(ctx, *hours)
	if err != nil {
		fmt.Fprintf(stderr, "import failed: %v\n", err)
		return 1
	}
	if len(entries) == 0 {
		fmt.Fprintln(stderr, "no family-labelled detections returned; refusing to replace any existing candidate")
		return 1
	}
	generated := now().UTC().Truncate(time.Second)
	doc := candidate{
		Version: *version,
		GeneratedAt: generated.Format(time.RFC3339),
		ExpiresAt: generated.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		Entries: entries,
	}
	payload, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "encode candidate: %v\n", err)
		return 1
	}
	payload = append(payload, '\n')

	// O_EXCL avoids silently overwriting a previous candidate. The operator must
	// review and explicitly remove/rename it before creating another candidate.
	file, err := os.OpenFile(*outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			fmt.Fprintln(stderr, "output already exists; refusing to overwrite it")
			return 1
		}
		fmt.Fprintf(stderr, "create candidate: %v\n", err)
		return 1
	}
	_, writeErr := file.Write(payload)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(*outPath)
		fmt.Fprintln(stderr, "failed to write candidate; partial output removed")
		return 1
	}

	fmt.Fprintf(stdout, "Created UNSIGNED candidate: %s (%d SHA-256 entries, version %d)\n", *outPath, len(entries), *version)
	fmt.Fprintln(stdout, "This file is NOT trusted or scanner-active until reviewed and signed by the project publisher.")
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, time.Now, os.Stdout, os.Stderr))
}
