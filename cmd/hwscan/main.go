package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/lordkeremello45/HWcontrol-Security/internal/scanner"
)

func main() {
	root := flag.String("root", "", "directory to scan (required)")
	hashes := flag.String("hashes", "", "optional newline-separated SHA-256 denylist")
	jsonOutput := flag.Bool("json", false, "emit machine-readable JSON")
	flag.Parse()

	if *root == "" {
		fmt.Fprintln(os.Stderr, "error: -root is required")
		os.Exit(2)
	}
	denylist, err := scanner.LoadSHA256List(*hashes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	result, err := scanner.ScanRoot(*root, denylist)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fmt.Fprintln(os.Stderr, "error: encode result:", err)
			os.Exit(2)
		}
	} else {
		for _, finding := range result.Findings {
			fmt.Printf("DETECTED  %s  %s  %s\n", finding.Path, finding.SHA256, finding.Reason)
		}
		for _, scanErr := range result.Errors {
			fmt.Printf("INCOMPLETE %s\n", scanErr)
		}
		fmt.Printf("Scanned %d regular files; %d finding(s); %d issue(s).\n",
			result.FilesScanned, len(result.Findings), len(result.Errors))
	}

	if len(result.Errors) > 0 {
		os.Exit(3)
	}
	if len(result.Findings) > 0 {
		os.Exit(1)
	}
}
