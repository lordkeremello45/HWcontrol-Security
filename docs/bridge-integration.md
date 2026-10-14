# HWcontrol2.0 Bridge integration contract

**Status: DESIGN PROPOSAL — NOT IMPLEMENTED.** This document defines a safe integration boundary for the existing read-only scanner. It does not claim that HWcontrol2.0 currently exposes these types, endpoints, or behaviors.

## Architecture boundary

Keep the existing trust direction:

`Flutter/Dart UI → authenticated localhost Go Bridge → native C++ engine`

The scanner is a separate read-only security capability. It must not receive hardware-control authority and must not be allowed to change Bridge authentication, native-engine validation, OS permissions, or update trust decisions.

- The UI may request a scan and display the result. UI state is never authorization.
- The Go Bridge must authenticate and authorize every request independently of the UI.
- The Bridge must validate and canonicalize requested scan scope, apply resource limits, and reject unsupported paths before invoking the scanner.
- The scanner must remain read-only. Findings must never directly trigger deletion, quarantine, process termination, privilege elevation, or hardware-control actions.
- Ada/SPARK policy may add deterministic decision checks only after the surrounding code supplies trustworthy facts. Boolean values received from a UI or arbitrary caller do not prove authentication, consent, signature validity, or replay protection.
- AI output is explanatory only and cannot authorize a scan, update, remediation, or hardware action.

## Proposed request/result model

These are language-neutral design fields, not an implemented API.

### Scan request

- `request_id`: unpredictable identifier generated/validated by the Bridge to correlate a response; do not treat it alone as authentication or replay protection.
- `scope_id`: preferably a Bridge-managed, allowlisted scope identifier. If arbitrary paths are supported later, require explicit user selection and Bridge-side validation.
- `mode`: initially only `read_only`.
- `deadline_ms` and resource limits: Bridge-enforced bounds for elapsed time, number of files, bytes read, and maximum findings/errors.
- `intelligence_version`: optional identifier for the locally installed denylist. A hash list must not be accepted as trusted merely because it has a checksum.

Do not accept caller-supplied flags such as `authenticated=true`, `signature_valid=true`, `user_consented=true`, or `hardware_policy_allowed=true` as evidence. The Bridge must derive security facts from its own verified state and trusted verification routines.

### Scan result

- `status`: `CLEAN`, `FINDINGS`, `INCOMPLETE`, or `ERROR`.
- `files_scanned`: non-negative count.
- `findings`: path relative to the approved scan root, SHA-256 digest, and a stable reason code.
- `issues`: bounded, sanitized diagnostics. Avoid returning secrets, full environment data, or unnecessary absolute paths.
- `intelligence_version`: the exact local intelligence version used, or absent when no intelligence was used.

Semantics are fail-safe: any traversal/read error, resource-limit termination, missing required intelligence, or incomplete enumeration must never be reported as `CLEAN`. A finding plus an error is still `INCOMPLETE` with findings preserved. A successful scan means only that the implemented checks completed for the selected scope; it does not mean the device is malware-free.

## IPC and authorization requirements

1. Prefer the existing authenticated Bridge channel rather than adding a second unauthenticated localhost listener.
2. Enforce request authentication, authorization, replay resistance, input validation, and size/time limits in the Bridge. Bind only to loopback if a listener is unavoidable; verify peer identity where the platform supports it.
3. Do not rely on CORS, an obscure port, a GUI-only check, or a shared static token embedded in the application as authentication.
4. Treat paths, filenames, denylist data, scan output, and diagnostic strings as untrusted input. Bound their lengths and escape them in logs/UI.
5. Run with least privilege. Do not elevate solely to increase scan coverage; report permission failures as incomplete.
6. Keep the scanner's result channel separate from hardware-control commands. A finding cannot directly authorize or trigger hardware actions.
7. Fail closed for policy or IPC failures: reject the requested security action and return a clear error, not a permissive fallback.
8. Do not add quarantine or deletion in this integration step. Any future remediation requires a separate reviewed design for explicit consent, isolated storage, restore, false-positive recovery, and platform-specific permissions.

## Implementation sequence and acceptance criteria

1. **Bridge inventory:** inspect the actual HWcontrol2.0 Bridge routing, authentication/session handling, IPC transport, error model, and tests before choosing an interface. Reuse existing mechanisms where they meet these requirements.
2. **Contract tests:** test unauthenticated requests, invalid/oversized paths, path traversal and symlink cases, replayed requests, time/resource limits, unavailable scanner, malformed result data, and mixed findings/errors.
3. **Adapter:** add a narrow Go adapter around the scanner only after the Bridge inventory. It must not expose arbitrary process execution or accept policy booleans from the UI.
4. **Policy boundary:** if Ada/SPARK is called across a process or FFI boundary, define a versioned, validated protocol and test malformed, missing, stale, and inconsistent responses. Do not claim end-to-end proof based on the isolated policy package.
5. **Packaging:** package the scanner and required data through the existing per-platform packaging mechanisms only after the integration works in tests. Do not bundle an unauthenticated or unsigned threat-intelligence feed.
6. **Platform verification:** independently run integration and installer tests on Windows 10/11 x64, supported Debian/Ubuntu-family Linux x64, and macOS 14+ Apple Silicon. Unavailable environments remain explicitly unverified.

## Explicit non-goals

This step does not implement real-time monitoring, broad malware-family detection, behavioral analysis, automatic intelligence updates, quarantine, automatic remediation, or OS-wide antivirus protection. It must not disable or replace Microsoft Defender or other platform security software.
