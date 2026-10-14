# Read-only scanner (initial implementation)

**Status: IMPLEMENTED, NOT YET INTEGRATED INTO HWcontrol2.0.** This tool is an initial local scanning component, not a complete antivirus product.

## Build and test

```sh
go test -race ./...
go vet ./...
go build ./cmd/hwscan
```

## Scan a directory

```sh
go run ./cmd/hwscan -root ./directory-to-scan
```

JSON output:

```sh
go run ./cmd/hwscan -root ./directory-to-scan -json
```

To use a local SHA-256 denylist, pass a UTF-8 text file containing one 64-character hexadecimal SHA-256 digest per line. Blank lines and lines beginning with `#` are ignored.

```sh
go run ./cmd/hwscan -root ./directory-to-scan -hashes ./known-bad-sha256.txt
```

Exit codes:
- `0`: scan completed with no findings.
- `1`: one or more findings.
- `2`: invalid arguments/configuration or scan could not start.
- `3`: scan was incomplete because one or more entries could not be inspected.

A scan with errors is not a clean bill of health. Review the error list and rescan after resolving access or filesystem issues.

## Current detections

- Exact EICAR antivirus test string, including when it spans input-buffer boundaries.
- Exact SHA-256 matches from an explicitly supplied denylist.

The EICAR string is a harmless industry-standard test pattern, not malware. A hash match means only that bytes match a listed digest. It does not establish who published the file, whether the denylist is authentic, or whether an unmatched file is safe.

## Safety and limitations

- The scanner never executes, deletes, quarantines, repairs, or modifies files.
- Symlink roots are rejected; symlink and non-regular entries below the root are skipped and recorded as scan issues.
- The scan is best-effort and cannot establish that a live operating system is malware-free.
- It does not yet provide broad malware signatures, heuristic/behavioral detection, archive recursion, memory scanning, real-time monitoring, automatic signature updates, quarantine, or false-positive review.
- It is not yet wired into HWcontrol2.0's GUI, Go Bridge, installer, or update flow. Do not describe it as an integrated product feature until those changes are implemented and tested.
- This initial implementation uses Go's portable file APIs; filesystem race resistance and platform-specific hardening require additional review before privileged or unattended use.
- Continue to use and keep enabled the platform's established security software, including Microsoft Defender where applicable. This tool does not attempt to replace or disable it.

## Safe next integration steps

1. Define an explicit scan request/result contract between the HWcontrol2.0 UI and local security service; validate paths and authorization in the service, not the UI.
2. Run scans with least privilege and bounded resource use; never grant the scanner hardware-control authority.
3. Treat scan errors and stale/unavailable intelligence as **INCOMPLETE/UNKNOWN**, never as clean.
4. Add authenticated, signed threat-intelligence distribution before shipping any denylist; a checksum alone is not publisher authentication.
5. Add consent-based remediation only after quarantine storage, rollback, false-positive recovery, and platform-specific permission handling have been reviewed.
6. Add integration tests and installer/package validation for Windows 10/11 x64, Linux x64, and macOS 14+ Apple Silicon independently.
