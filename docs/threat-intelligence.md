# Threat-intelligence ingestion

**Status: SIGNATURE VERIFIER AND UNSIGNED MALWAREBAZAAR CANDIDATE IMPORTER IMPLEMENTED IN THIS FEATURE BRANCH. NO PRODUCTION FEED, TRUSTED PUBLISHER KEY, OR AUTOMATIC UPDATE IS CONFIGURED.**

## Initial provider

The adapter targets the official MalwareBazaar Community API endpoint, `https://mb-api.abuse.ch/api/v1/`, using its `recent_detections` query. The provider requires an Auth-Key and states that community use is subject to fair-use terms; commercial or for-profit use may require an enhanced commercial API subscription. Review current terms before shipping or redistributing data.

Official references:
- API and response fields: https://bazaar.abuse.ch/api/
- FAQ and fair-use notes: https://bazaar.abuse.ch/faq/
- Provider source repository: https://github.com/abusech/MalwareBazaar

The importer retrieves hash metadata only. It does **not** download malware samples, submit files, execute samples, or upload local information. It consumes only SHA-256 and family-label fields; extra upstream metadata is ignored.

## Create an unsigned candidate snapshot

From the repository root:

```sh
go test -race ./...
go run ./cmd/hwintel-import -hours 48 -version 1 -out threat-intel-candidate.json
```

Set `MALWAREBAZAAR_AUTH_KEY` through local secret storage or a shell environment. Do not put it in source code, command-line arguments, logs, issue reports, or commits. The importer sends it in the HTTPS `Auth-Key` header to the fixed official endpoint; redirects are not followed.

The importer:
- limits the query window to 1–168 hours;
- uses bounded request timeouts and response size;
- rejects malformed responses, invalid SHA-256 digests and missing family labels;
- de-duplicates repeated digests;
- creates the candidate with restrictive local permissions and refuses to overwrite an existing file;
- marks the output as unsigned and does not activate it.

The default output expires seven days after generation. This is a candidate policy value, not a claim that provider data is complete or guaranteed current.

## Review and signing gate

The output JSON matches the schema accepted by `internal/threatintel.VerifyAndLoad`, but **it is unsigned and must be rejected by the verifier until signed**.

Before publication:
1. Review provider terms, record provenance, unexpected volume changes and false-positive handling.
2. Validate that every record maps to the provider's SHA-256 field and family label as expected.
3. Assign a monotonically increasing release version using the project's release process.
4. Sign the exact candidate bytes with the project's offline Ed25519 release key. Keep the private key outside the repository and end-user installations.
5. Publish the payload and detached signature through a controlled release process; provision the public key independently from the feed.
6. Test tampering, expired feeds, key rotation, rollback, interrupted download, and recovery before connecting this to automatic updates.

Do not add a private signing key or production API key to this repository. HTTPS authenticates the endpoint during retrieval; it does not make an arbitrary downloaded file an independently verifiable signed release artifact.

## Current detection scope and limits

The scanner currently detects the EICAR test string and exact SHA-256 values supplied by its caller. The candidate importer is not connected to scanner runtime. Even after a signed database is integrated, hash matching detects exact known samples represented by the feed; it does not establish broad malware-family coverage, behavior detection, memory scanning, backdoor prevention, or real-time OS-wide protection.

SHA-256 is the initial file identifier. Adding every SHA family does not substitute for trustworthy threat intelligence, behavioral detection, or operating-system access controls. Keep Microsoft Defender and other established platform security products enabled.
