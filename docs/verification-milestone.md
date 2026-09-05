# Verification and authority hardening milestone

This follows the [initial audit](current-state-audit.md). It is a bounded improvement
to the existing implementation, not completion of the program charter.

## Changes

- Reused the existing encoded-path fix from commit
  `566bf3c790ade74c1c9adc14540c6dda11d795a0`, including its regression artifacts.
- Policy-engine errors now deny all impact tiers and mint no capability. See
  [ADR 0055](adr/0055-policy-outages-do-not-grant-read-authority.md).
- Process-inspector failures no longer become a false report that a process exited.
  Unknown identity remains a refusal to signal, rather than successful containment.
- Core accepts the hex seed files produced by the CLI as well as existing binary
  seeds. Malformed files are rejected; production startup still requires real keys.
- Deployment tests select the versioned policy directory bundled in the image,
  avoiding the flattened ConfigMap that hid required policy/remit/manifest paths.
- Empty identity registrations render as lists, including a Gateway with no agent
  registrations when only human operators are configured.
- The Kubernetes check runs on PRs, preserves its negative and reachability controls,
  captures startup diagnostics, and separates expected curl timeouts from transport
  errors. It is explicitly a network-isolation check, not proof of authenticated
  capability execution through the deployed service.
- Secret-scanner triage uses 17 exact historical fingerprints for inspected Swift
  type annotations and nonfunctional canary templates. No rule or directory was
  disabled by this change. Future occurrences remain scanned.

## Local verification

Rust 1.88.0 and the Python SDK development environment were installed for this work.
The following checks were executed successfully during development:

| Check | Result |
|---|---|
| Core, Gateway and detector Rust suites | 173 tests passed |
| Core failure and end-to-end subset | 22 tests passed; included in the above total |
| CLI adversarial suite | 25 tests passed |
| New process-inspector error regression | Passed |
| Core key-file regressions | 2 tests passed; included in the Core total |
| Python SDK | 38 tests passed |
| HTTP probe error classification | 4 tests passed |
| Clippy with warnings denied | Passed |
| Helm lint/render | Passed, including empty and human-only registration cases |
| Service startup smoke | Core and Gateway health passed using generated keys and rendered configurations adapted to local paths/listen addresses |
| Reviewer demo | Completed using a temporary workspace |
| Formatting, generated inventory and Markdown links | Passed |

These are local observations, not substitutes for CI at the final PR commit.
The complete local workspace run exposed process-table-dependent failures: `/bin/ps`
reports a library error in this environment. Those tests were not removed or skipped
in CI. Docker/Kubernetes and native macOS execution are validated by their respective
CI jobs; native compile/parity tests do not establish entitled device activation.

## Remaining release gates

1. Require a green final-commit workflow, including fuzz and Kubernetes, before
   treating the repaired baseline as verified. Feature-branch CI does not change the
   default branch until integration.
2. Implement separately owned local service state and authenticated IPC before
   claiming the protected agent cannot approve itself or rewrite authority/audit data.
3. Prove an authenticated permitted action and matched rejection through the deployed
   Gateway with observable tool effects. The current reference Gateway registers
   recording backends and does not supply that production transport proof.
4. Validate signed, entitled macOS activation and direct-bypass tests on dedicated
   devices before promoting complete process confinement.
5. Add delegation attenuation, comparative experiments, benign-utility measurements,
   ablations and the paper artifact behind their own evidence gates.

The existing [enforcement matrix](security/ENFORCEMENT_STATUS.md) remains the source
of truth. No native boundary is promoted by these changes.
