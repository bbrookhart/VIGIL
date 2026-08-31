# Release readiness record

## Decision

**Current state: NO-GO for a public release.** This document is a commit-specific gate, not a
forecast. The repository should remain private until all blocking rows have exact evidence.

| Gate | Current status | Required evidence |
|---|---|---|
| Candidate commit | Pending | Full SHA selected after review |
| Required CI | Pending | Green workflow URL for that SHA |
| Secret/history review | Pending | Scanner output plus manual false-positive disposition |
| Claim consistency | In review | README, status, invariants and roadmap cross-check |
| License/community files | In review | Intentional license and public contact paths |
| Metadata/social preview | Prepared, not applied | Repository settings screenshot/review |
| Recruiter demo | Pending execution on toolchain-equipped host | Transcript or CI artifact |
| Native enforcement | Explicitly not a v0.1 claim | Canonical status remains native-ready, not activated |
| Independent review | Pending | Named reviewer and findings disposition |

## Release scope

The proposed `v0.1.0` is a **research preview** of the portable control plane, semantic brokers,
evaluation artifacts and entitlement-free native adapter/product paths. It must not be marketed as
a production macOS sandbox or complete endpoint product.

## Sign-off template

```text
Candidate SHA:
CI run:
SBOM artifact:
Secret/history scan:
Known vulnerabilities and disposition:
Documentation/claim reviewer:
Clean-room demo reviewer:
Native status confirmed as:
Residual risks accepted by:
Decision and UTC time:
```

See [publication checklist](PUBLICATION_CHECKLIST.md) for the complete gate list.
