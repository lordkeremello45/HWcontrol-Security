# Threat-intelligence feed — first secure ingestion step

**Status: VERIFIER IMPLEMENTED IN FEATURE BRANCH; NO LIVE FEED OR PRODUCTION TRUST KEY CONFIGURED.**

This package is a validation boundary, not a malware database subscription and not an automatic updater. It intentionally does not download data, embed a public key, install a feed, or change scanner behavior.

## Signed snapshot format

The publisher produces a UTF-8 JSON payload with this schema:

```json
{
  "version": 1,
  "generated_at": "2026-10-14T00:00:00Z",
  "expires_at": "2026-10-21T00:00:00Z",
  "entries": [
    {
      "sha256": "64 lowercase hexadecimal characters",
      "family": "publisher-defined label",
      "source": "feed or rule provenance label"
    }
  ]
}
```

The detached signature is a 128-character hexadecimal Ed25519 signature over the **exact payload bytes**. Any byte-level change invalidates the signature. The public key must come from a trusted, independently provisioned configuration or signed application release; downloading a key next to the feed does not establish trust.

The verifier fails closed for invalid signatures, invalid key/signature encoding, unknown JSON fields, trailing data, invalid or duplicate digests, invalid timestamps, expired/not-yet-valid snapshots, oversized payloads, excessive entries, and versions below the caller's persisted minimum accepted version.

## Integration requirements before production use

1. Select a reputable threat-intelligence provider and verify its licensing, redistribution terms, update cadence, hash semantics, and false-positive reporting process.
2. Implement the feed adapter for that provider's actual format; do not relabel an arbitrary dataset as an official malware database.
3. Generate and provision a production Ed25519 key outside source control. Define key rotation and recovery before release.
4. Persist the highest accepted version in tamper-resistant state appropriate to each platform. A caller-supplied minimum alone is not durable anti-rollback protection.
5. Verify the signature before parsing and indexing. Keep download size, timeout, redirect policy, decompression and storage limits bounded.
6. Atomically stage and activate only a verified snapshot. Preserve the last known-good database when refresh fails; mark intelligence stale/unknown once the prior snapshot expires.
7. Record feed name, version, generation/expiry timestamps, and digest for diagnostics. Do not upload user files or telemetry to the feed provider.
8. Keep scanning read-only. A match is a finding, not authority to delete files, quarantine them, kill processes, or change hardware permissions.
9. Test the end-to-end updater, trusted key lifecycle, persistence, rollback, interrupted writes, stale feeds, false positives and all supported platforms.

## Detection scope

The initial scanner currently recognizes the exact EICAR test string and exact SHA-256 hashes supplied by a caller. Loading an authenticated database is a prerequisite for trustworthy hash matching, but does not provide broad detection by itself. Hashes only identify exact byte sequences already represented in the feed; they do not detect unknown variants, behavior, memory-only threats, or a live backdoor.

SHA-256 remains the initial file-identification algorithm. Adding SHA-512 or SHA-3 digests can help with independent integrity formats, but running every SHA variant does not increase malware intelligence coverage. The feed publisher's authenticated signature is the trust control; a checksum alone is not publisher authentication.

Keep Microsoft Defender and other established platform security products enabled. This work does not claim real-time OS-wide protection or the ability to block a privileged attacker.
