# Ada/SPARK security policy core

**Status: IMPLEMENTED AS AN ISOLATED POLICY PROTOTYPE; NOT INTEGRATED OR FORMALLY PROVED.**

This package is a deterministic, fail-closed policy decision function. It is deliberately small so its conditions can be reviewed and subjected to SPARK analysis.

## Rules

Every action requires an authenticated request, replay protection to have passed, and validated inputs. In addition:

- Threat-intelligence updates require a valid publisher signature and an accepted version/rollback decision.
- Quarantine requires explicit user consent.
- Hardware control requires a separate deterministic hardware policy to approve the action.
- Missing any required condition results in `Deny`.

The package does not implement authentication, replay protection, cryptographic signature verification, rollback storage, user-consent UI, or hardware controls. Those are trusted inputs supplied by the caller and must be established independently. A caller must not fabricate these flags from GUI state or AI output.

## Build and smoke test

With GNAT and GPRbuild installed:

```sh
gprbuild -P ada/security_policy.gpr
./ada/obj/policy_smoke_test
```

The smoke test exhaustively checks all 512 combinations (4 actions × 2⁷ Boolean input combinations) against an independently written expected-decision table using Ada assertions. This catches decision-table regressions but is not a formal proof.

## SPARK proof

With a compatible GNATprove installation:

```sh
gnatprove -P ada/security_policy.gpr --mode=prove
```

Record the exact GNATprove version and result before marking the package `VERIFIED`. Do not treat the contracts alone as evidence that the surrounding Go, C++, operating-system, or cryptographic components are proved.

## Integration constraints

- The Go Bridge must enforce authentication and authorization itself; this policy is an additional layer, not a replacement.
- Keep hardware-control authorization in deterministic code, never in an AI model.
- Use established cryptographic libraries and secure key storage for signatures.
- Reject requests when the policy service fails or its response cannot be validated.
- Keep scanning read-only. Do not add automatic deletion or quarantine without a separately reviewed consent and recovery flow.
- This prototype has no FFI/IPC binding to Go yet and must not be treated as an active security boundary until the interface is designed, authenticated, tested, and integrated.
