# HWcontrol Security

HWcontrol Security is the defensive security layer for [HWcontrol2.0](https://github.com/lordkeremello45/HWcontrol2.0), not a general-purpose antivirus replacement.

## Current status

- **DOCUMENTED IN HWcontrol2.0:** the main repository's [security policy](https://github.com/lordkeremello45/HWcontrol2.0/blob/main/SECURITY.md) describes bridge authentication, integrity monitoring, SPARK policy, and release-integrity controls. Their actual implementation and test status must be verified against code and CI before treating them as verified capabilities.
- **IMPLEMENTED HERE (initial stage):** a separately testable, read-only local scanner for exact SHA-256 denylist matches and the standard EICAR test string. It is not yet integrated into HWcontrol2.0.
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

## Security policy core (Ada/SPARK prototype)\n\nAn isolated Ada policy prototype lives in [`ada/`](ada/). It denies actions unless authentication, replay protection, and input validation have already passed; update signatures/version policy, quarantine consent, and hardware policy are action-specific gates. It is **not yet connected to the Go Bridge and has not been formally proved**. See [the policy notes](docs/spark-policy.md).\n\n## Development\n
The scanner implementation and tests live in this repository. Do not treat the project as production antivirus until threat intelligence, authenticated update delivery, false-positive handling, a safe user-authorized response workflow, and platform-specific testing are implemented and reviewed.

## Related project

- [HWcontrol2.0 source](https://github.com/lordkeremello45/HWcontrol2.0)
- [HWcontrol2.0 security policy](https://github.com/lordkeremello45/HWcontrol2.0/blob/main/SECURITY.md)
