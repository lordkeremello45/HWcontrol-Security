# HWcontrol2.0 Bridge integration contract

**Status: DESIGN PROPOSAL — PROTOCOL HELPERS IMPLEMENTED, LIVE INTEGRATION NOT IMPLEMENTED.** This document is based on a read of `HWcontrol2.0/bridge_service/src/main.go`, `main_test.go`, `bridge_service/go.mod`, and `SECURITY.md` on the current `main` branch. The protocol helper is isolated and must not be mistaken for a live Bridge action.

## Verified Bridge facts and integration blockers

- The Bridge currently uses a `Command` with `action`, `value`, optional `target`, `timestamp`, `nonce`, and `auth` fields.
- Its HMAC-SHA-256 payload currently signs action, a six-decimal formatted value, timestamp, nonce, and `target` only when present. The current validator permits `target` only for `Set Fan Channel`.
- The validator uses an explicit action allowlist and enforces a 64 KiB request bound, timestamp window, nonce format, and authentication format. Tests cover command authentication, replay protection, unsupported actions, and request size.
- The current Bridge module declares Go 1.22. The security scanner uses Go's `os.Root` API and the security repository's `go.mod` targets Go 1.26.9. The scanner package therefore cannot simply be imported into the current Bridge module without an intentional toolchain-compatibility change.
- The Bridge currently has no scan request/result contract. Do not overload `target` with a filesystem path, because the existing validator deliberately reserves it for fan-channel identifiers.

Before implementation, choose and review one of these approaches:

1. **Raise and validate the Bridge Go toolchain** to a compatible supported version, then import a versioned scanner library with tests. This requires reviewing all build/package workflows and the minimum supported Go runtime.
2. **Ship a separate, fixed security-scanner executable** and invoke it only through a fixed executable path and argument list (never a shell). Bound runtime, stdout/stderr and JSON response size; validate the executable's installation integrity; treat its output as untrusted; and report launch failure/timeouts as `INCOMPLETE` or `ERROR`. This adds process lifecycle and packaging complexity that must be tested per platform.

Do not choose one silently or make a runtime/toolchain change as a side effect of adding a scan action.

## Protocol helper implemented for contract tests

The isolated Go helper is `internal/scanprotocol/scan_request_v1.go`; the Dart counterpart is `gui_dashboard/lib/security/scan_request_v1.dart` in HWcontrol2.0. Neither is connected to the active Bridge protocol or GUI command flow. Their shared fixture is `internal/scanprotocol/testdata/scan_request_v1.json` in this repository and `gui_dashboard/test/fixtures/scan_request_v1.json` in HWcontrol2.0. The fixture key is a public test-only key and must never be used in production.

Canonical UTF-8 payload fields, joined with a single LF byte and no trailing newline:

1. `HWSECURITY-SCAN-V1`
2. `scan`
3. `scope_id` (lowercase allowlisted identifier; 1–64 characters)
4. `read_only`
5. positive Unix timestamp in milliseconds, base-10 with no leading zeroes
6. nonce, exactly 32 hexadecimal characters and canonicalized to lowercase
7. request ID, 1–64 ASCII letters, digits, dot, underscore, or hyphen

The HMAC-SHA-256 tag is lowercase hexadecimal over exactly those UTF-8 bytes. The fixture's expected tag is `40cb94069c89c83fa53eab998eba51a30716793ba436543964c63f027b2f3cc3`. Both language tests must reject any changed signed field and malformed field. This protocol version is a proposal for scan requests only; it does not replace or reinterpret existing hardware-control signatures.

## Architecture boundary

Keep the trust direction:

`Flutter/Dart UI → authenticated Go Bridge → native C++ engine`

The scanner is a separate read-only security capability. It must not receive hardware-control authority and must not change Bridge authentication, native-engine validation, OS permissions, or update trust decisions.

- The UI may request a scan and display the result. UI state is never authorization.
- The Go Bridge must authenticate and authorize every request independently of the UI.
- The Bridge must validate and canonicalize the requested scan scope, apply resource limits, and reject unsupported paths before invoking the scanner.
- The scanner must remain read-only. Findings must never directly trigger deletion, quarantine, process termination, privilege elevation, or hardware-control actions.
- Ada/SPARK policy may add deterministic decision checks only after surrounding code supplies trustworthy facts. Boolean values received from a UI or arbitrary caller do not prove authentication, consent, signature validity, or replay protection.
- AI output is explanatory only and cannot authorize a scan, update, remediation, or hardware action.

## Proposed request/result

Add a dedicated action such as `Scan Security` only after updating the Go Bridge validator, the Dart request signer, protocol tests, and all supported clients together. Do not repurpose `target`.

Prefer a Bridge-managed allowlisted scope identifier rather than an arbitrary path. Enforce limits on elapsed time, files, bytes read, findings, and diagnostic bytes. If a limit is reached, return `INCOMPLETE`, not `CLEAN`.

Use a versioned result containing `status` (`CLEAN`, `FINDINGS`, `INCOMPLETE`, `ERROR`), a non-negative file count, relative-path findings with SHA-256 and stable reason codes, bounded sanitized issues, and the exact local intelligence version if used. Any traversal/read error, limit termination, invalid helper output, timeout, or incomplete enumeration must never be reported as `CLEAN`. A completed scan only means implemented checks completed for the selected scope; it does not mean the device is malware-free.

## IPC and authorization requirements

1. Reuse the existing authenticated Bridge channel rather than adding a second unauthenticated localhost listener.
2. Enforce authentication, authorization, replay resistance, input validation, and size/time limits in the Bridge. Loopback binding alone is not authentication.
3. Do not rely on CORS, an obscure port, a GUI-only check, or a shared static token embedded in the application.
4. Treat paths, filenames, denylist data, scan output, and diagnostic strings as untrusted input. Bound lengths and escape them in logs/UI.
5. Keep scan results separate from hardware-control commands. A finding cannot directly authorize or trigger hardware actions.
6. Fail closed for policy or IPC failures: reject the requested security action and return a clear error, not a permissive fallback.
7. Do not add quarantine or deletion in this integration step. Future remediation requires separate review for explicit consent, isolated storage, restore, false-positive recovery, and platform-specific permissions.

## Ada/SPARK boundary

The existing Ada package is an isolated policy unit, not a callable Bridge service. Do not mark it as the active authorization boundary until its transport is designed and validated. If called across FFI or process boundaries, define a versioned protocol and test malformed, missing, stale, and inconsistent responses. Any unknown decision or policy failure must deny the requested security action. Do not claim end-to-end proof based on the isolated policy package.

## Implementation sequence and acceptance criteria

1. Decide between scanner-library import and fixed helper executable; document minimum Go/runtime requirements and packaging impact.
2. Run the shared Go and Dart HMAC fixture tests and publish the same canonical test vector before changing either live protocol.
3. Add contract tests for unauthenticated requests, tampered scope/mode, invalid/oversized paths, path traversal and symlinks, replayed requests, time/resource limits, unavailable scanner, malformed results, and mixed findings/errors.
4. Add a narrow scan adapter only after the toolchain decision. It must not expose arbitrary process execution or accept policy booleans from the UI.
5. Package the scanner and required data only after integration tests pass. Do not bundle an unauthenticated or unsigned threat-intelligence feed.
6. Independently test Windows 10/11 x64, supported Debian/Ubuntu-family Linux x64, and macOS 14+ Apple Silicon. Unavailable environments remain explicitly unverified.

## Explicit non-goals

This step does not implement real-time monitoring, broad malware-family detection, behavioral analysis, automatic intelligence updates, quarantine, automatic remediation, or OS-wide antivirus protection. It must not disable or replace Microsoft Defender or other platform security software.
