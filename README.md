# HWcontrol Security

HWcontrol Security is the defensive security layer for [HWcontrol2.0](https://github.com/lordkeremello45/HWcontrol2.0), not a general-purpose antivirus replacement.

## Current status

- **IMPLEMENTED HERE (initial stage):** a separately testable, read-only local scanner for exact SHA-256 denylist matches and the standard EICAR test string. It is not yet integrated into HWcontrol2.0.
- **IMPLEMENTED IN THIS FEATURE BRANCH:** an isolated Ed25519-signed threat-intelligence snapshot verifier with expiry, version-floor, schema, digest, duplicate-entry, and size checks. No production feed, trusted publisher key, downloader, or scanner integration is configured; see [the feed contract](docs/threat-intelligence.md).
- **IMPLEMENTED AS A PROTOTYPE:** an isolated Ada/SPARK policy unit with deterministic fail-closed rules. Its CI proof covers that unit and its modeled assumptions only; it is not integrated into the Go Bridge and does not prove end-to-end authorization.
- **NOT CLAIMED:** broad malware-family coverage, behavioral detection, real-time operating-system-wide protection, automatic remediation, or replacement of Microsoft Defender/other platform security tools.

## Security principles

1. Read-only by default. Never delete, quarantine, modify, or execute scanned files.
2. A hash match is a detection indicator, not publisher authentication; a hash list is only as trustworthy as its distribution and update channel.
3. Fail safely on malformed configuration, unreadable files, unsupported paths, and resource limits.
4. AI components may explain findings but never make authorization, signature-verification, or hardware-control decisions.
5. Keep HWcontrol2.0's security boundaries intact: Flutter/Dart UI → authenticated Go Bridge → native engine, with deterministic SPARK policy where applicable.
6. Integrate with existing OS security software rather than disabling or replacing it.

## Platform targets

Windows 10/11 x64, Debian/Ubuntu-family Linux x64, and macOS 14+ Apple Silicon are project targets. Each capability must be validated independently on each platform before being marked VERIFIED.

## Security policy core (Ada/SPARK prototype)

The isolated policy prototype lives in [`ada/`](ada/). It denies actions unless authentication, replay protection, and input validation have already passed; update signature/version policy, quarantine consent, and hardware policy are action-specific gates. The current policy CI compile, truth-table tests, and GNATprove run passed, but the unit is not connected to the Go Bridge. See [the policy notes](docs/spark-policy.md).

## Bridge integration

The proposed, not-yet-implemented interface and acceptance criteria are documented in [the Bridge integration contract](docs/bridge-integration.md). The actual HWcontrol2.0 Bridge must be inspected before selecting concrete routes, IPC messages, or adapters.

## Development

Do not treat the project as production antivirus until threat intelligence, authenticated update delivery, false-positive handling, a safe user-authorized response workflow, integration testing, and platform-specific validation are implemented and reviewed.

## Related project

- [HWcontrol2.0 source](https://github.com/lordkeremello45/HWcontrol2.0)
- [HWcontrol2.0 security policy](https://github.com/lordkeremello45/HWcontrol2.0/blob/main/SECURITY.md)


## Threat intelligence

See [the threat-intelligence ingestion contract](docs/threat-intelligence.md) for the signed snapshot verifier and unsigned MalwareBazaar candidate importer. No production feed or automatic update is enabled.


## File-format scope

The scanner evaluates regular files without requiring a recognized extension and reports basic file-format classifications. Initial magic-byte recognition covers common PE/ELF/Mach-O binaries, ZIP/7z/RAR/gzip/xz/zstd/TAR archives, CAB/OLE containers, Debian/RPM packages and WASM. Extension hints also cover common Windows, macOS and Linux package, library, and script suffixes. This is an initial classifier only: it does not yet unpack and recursively inspect archives or verify every platform package signature. See [scanner limitations and format scope](docs/scanner.md).
