# HWcontrol Security

HWcontrol Security is the defensive security layer for [HWcontrol2.0](https://github.com/lordkeremello45/HWcontrol2.0), not a general-purpose antivirus replacement.

## Current status

- **IMPLEMENTED IN HWcontrol2.0:** bridge request authentication and replay protection, runtime integrity monitoring, a separate Security Guardian/canary, a SPARK fail-closed hardware-control policy, and release checksum/provenance workflows are documented in the main repository's [security policy](https://github.com/lordkeremello45/HWcontrol2.0/blob/main/SECURITY.md).
- **PLANNED HERE:** a separately testable, read-only local file scanner that can apply an explicit SHA-256 denylist and detect the standard EICAR antivirus test string.
- **NOT CLAIMED:** broad malware-family coverage, behavioral detection, real-time operating-system-wide protection, automatic remediation, or replacement of Microsoft Defender/other platform security tools.

## Security principles

1. Read-only by default. Never delete, quarantine, modify, or execute scanned files.
2. A hash match is a detection indicator, not publisher authentication; a hash allowlist/denylist is only as trustworthy as its distribution and update channel.
3. Fail safely on malformed configuration, unreadable files, unsupported paths, and resource limits.
4. AI components may explain findings but never make authorization, signature-verification, or hardware-control decisions.
5. Keep HWcontrol2.0's security boundaries intact: Flutter/Dart UI → authenticated Go Bridge → native engine, with deterministic SPARK policy where applicable.
6. Integrate with existing OS security software rather than disabling or replacing it.

## Platform targets

Windows 10/11 x64, Debian/Ubuntu-family Linux x64, and macOS 14+ Apple Silicon are project targets. Each capability must be validated independently on each platform before being marked VERIFIED.

## Development

The scanner implementation and tests will live in this repository. Do not treat the project as production antivirus until threat intelligence, authenticated update delivery, false-positive handling, a safe user-authorized response workflow, and platform-specific testing are implemented and reviewed.

## Related project

- [HWcontrol2.0 source](https://github.com/lordkeremello45/HWcontrol2.0)
- [HWcontrol2.0 security policy](https://github.com/lordkeremello45/HWcontrol2.0/blob/main/SECURITY.md)
