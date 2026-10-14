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

## Exit codes

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
- The scanner anchors file opens to a Go 1.24+ `os.Root` handle and checks that the opened root matches the initial directory. This reduces path-replacement and traversal risk, but does not eliminate every filesystem race or replace platform-specific review. Run it without elevated privileges unless a documented use case requires otherwise.
- Continue to use and keep enabled the platform's established security software, including Microsoft Defender where applicable. This tool does not attempt to replace or disable it.

## Research references

- [Go: Traversal-resistant file APIs (`os.Root`)](https://go.dev/blog/osroot) — rationale for anchoring file access to a directory handle.
- [YARA documentation](https://yara.readthedocs.io/en/stable/) — established rule-based file pattern detection; evaluate as a later detection engine rather than inventing a proprietary rule language.
- [NIST SP 800-83 Rev. 1](https://csrc.nist.gov/pubs/sp/800/83/r1/final) — malware prevention, handling, and incident-response guidance.

## Safe next integration steps

1. Inspect the actual HWcontrol2.0 Bridge authentication, routing, IPC transport, and tests before selecting a concrete interface. See the [proposed integration contract](bridge-integration.md).
2. Run scans with least privilege and bounded resource use; never grant the scanner hardware-control authority.
3. Treat scan errors and stale/unavailable intelligence as **INCOMPLETE/UNKNOWN**, never as clean.
4. Add authenticated, signed threat-intelligence distribution before shipping any denylist; a checksum alone is not publisher authentication.
5. Add consent-based remediation only after quarantine storage, rollback, false-positive recovery, and platform-specific permission handling have been reviewed.
6. Add integration tests and installer/package validation for Windows 10/11 x64, Linux x64, and macOS 14+ Apple Silicon independently.


## File-format classification (initial implementation)

The scanner hashes and checks every regular file it can safely open, regardless of filename extension. JSON results now include `files_by_type`; detections include a `file_type` classification. The classifier checks a limited set of magic-byte signatures first (including PE/MZ, ELF, Mach-O/fat, ZIP, 7z, RAR, gzip, xz, zstd, CAB, OLE, Debian, RPM, WASM and TAR) and falls back to an extension-based hint when no known signature is found. Files with no extension are classified as `unknown:extensionless` unless a recognized signature is present.

**Important limitations:** this is identification, not complete parsing or malware detection. Some formats share signatures (for example ZIP-based installers), and the classifier does not validate package structure, signatures, nested archive contents, or all format variants. Extension fallback is explicitly not proof of actual format. Archive recursion and format-specific validation remain planned work.


## Bounded archive-member scanning

The scanner now inspects regular members of ZIP and uncompressed TAR archives without extracting files to disk. It applies limits of 4,096 members, 64 MiB per member, and 256 MiB total declared expansion per archive. Member content is checked against the same exact SHA-256 denylist and EICAR test pattern; findings identify the member as `outer-file!member-name`.

This is deliberately not recursive yet. gzip-compressed TAR, 7z, RAR, XIP, package-specific nested containers, encrypted archives, and nested archives are not unpacked by this step. Unsupported archive formats receive only an outer-file scan, so results must not imply full archive-content coverage. ZIP/TAR structural or member-read errors are reported as scan errors. Archive paths are labels only and are never extracted or used to write files.
