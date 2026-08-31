# Publication checklist

**Current recommendation:** keep the repository private until the candidate branch is green and
the manual metadata/security review below is complete. Public visibility is not itself proof of
release readiness.

## Automated gates

- [ ] Exact candidate commit has green required CI jobs.
- [ ] Generated evidence and local link checks pass.
- [ ] Rust formatting, Clippy and workspace tests pass.
- [ ] Python pytest, mypy and Ruff pass.
- [ ] Endpoint Security and Network Extension Swift suites pass on macOS.
- [ ] Cross-language fixtures regenerate with no diff.
- [ ] Policy/remit/manifest validation passes.
- [ ] Dependency audit, secret scan and SBOM jobs pass.
- [ ] Fuzz regression replay and smoke pass.
- [ ] Helm safety guards pass; kind non-bypassability passes on its configured trigger.

## Claim audit

- [ ] README counts equal `docs/generated/evidence.json` or are replaced with a generated include/link.
- [ ] No “passing” number is presented without an exact run link.
- [ ] No simulated, configured or entitlement-free result is called active OS enforcement.
- [ ] Brokered mediation is not described as process confinement.
- [ ] Benchmark statistics, hardware, toolchain and exclusions still match the report.
- [ ] Security model, invariant register and enforcement status agree.
- [ ] Roadmap items are not presented as shipped behavior.

## Secret, privacy and supply-chain audit

- [ ] Review the full Git history with an independent secret scanner and resolve every finding.
- [ ] Confirm `.gitleaks.toml` allowlists exact synthetic values/type declarations, not broad paths.
- [ ] Verify test fixtures contain no personal data, live endpoint, credential or signing identity.
- [ ] Review GitHub Actions permissions and pinned action SHAs.
- [ ] Review `Cargo.lock`, Python build metadata, container base images and Helm defaults.
- [ ] Inspect generated SBOM and current RustSec advisories.

## Repository presentation

- [ ] Apply [GitHub metadata](GITHUB_METADATA.md) description and topics.
- [ ] Render and upload the social preview; inspect cropping.
- [ ] Confirm license, contribution/security contacts and code of conduct are intentional.
- [ ] Confirm default branch protections and required checks.
- [ ] Resolve or explain stale/open pull requests before publication.
- [ ] Verify every README and `START_HERE` link as an anonymous reader.

## Native-product audit

- [ ] Replace development bundle/team placeholders before any signed distribution.
- [ ] Confirm no entitlement, installation or activated-device claim is implied by CI.
- [ ] Review app/System Extension identifiers and code requirements as one product graph.
- [ ] Confirm SIP, Gatekeeper and TCC are never weakened by instructions.
- [ ] Publish the native limitations beside any demo video or screenshot.

## Release decision

- [ ] Complete [release readiness](RELEASE_READINESS.md) with commit-specific evidence.
- [ ] Record one security reviewer and one clean-room reviewer.
- [ ] Tag only the audited commit.
- [ ] Publish checksums/SBOM and the research-preview release notes.
- [ ] Re-check links, badges, visibility and release assets after publication.

Any unchecked item that affects authenticity, secrets, license, or enforcement truth is a no-go.
