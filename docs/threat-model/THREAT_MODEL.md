# VIGIL Control Plane threat model

**Status:** living document, Phase 1 foundation

## Assets and security objectives

VIGIL protects user credentials, workspace integrity, host configuration, network authority,
policy, signing keys, audit evidence, and the reliability of agent/process attribution. The
primary objective is to prevent an agent from converting the human's ambient authority into
undeclared task authority.

## Threat actors

- Malicious prompt or content controlling an otherwise legitimate agent.
- Compromised model/provider, agent runtime, MCP server, local tool, or dependency.
- Malicious subagent attempting delegation or confused-deputy abuse.
- Local attacker attempting to disable VIGIL or alter evidence.
- User mistake induced by vague or repeated approval prompts.

## STRIDE analysis

| Class | Representative threat | Required control |
|---|---|---|
| Spoofing | environment variable claims another session | OS-verified audit identity and process provenance |
| Tampering | agent edits policy or SQLite evidence | OS deny, protected paths, signed policy, hash-chain verification |
| Repudiation | agent denies a child action | stable process identity, correlation, append-oriented events |
| Information disclosure | prompt injection reads SSH/cloud credentials | protected-resource deny and AUTH_OPEN enforcement |
| Denial of service | process/approval fan-out | quantitative budgets, prompt suppression, bounded queues |
| Elevation of privilege | child invokes `sudo` or persistence tools | non-transitive leases and AUTH_EXEC/file denial |

## Required attack cases

The adversarial suite must cover SSH-key reads, `curl | sh`, LaunchAgent writes, `security`,
`sudo`, nested interpreters, downloaded execution, direct-IP egress, `.env`-then-egress,
MCP writes outside workspace, MCP schema drift, symlink escape, child escalation, VIGIL/policy/
audit modification, approval flooding, slow exfiltration, AppleScript, confused deputies,
sensitive local sockets, concurrent exact-budget exhaustion, PID reuse, extension failure,
corrupt policy/audit events, clock changes, DNS rebinding, malicious package post-install, and
declared-intent/observed-execution mismatch.

Current automated coverage includes traversal, prefix confusion, symlink escape, unknown
capability denial, protected-resource simulation, capability replay/forgery, monotone policy,
atomic multi-dimensional budget boundaries under concurrency, broker denial before I/O, failed-I/O
refund, content-free file/process events, structured process execution, shell/interpreter denial,
environment clearing/allowlisting, bounded output, timeout termination, causal injection/egress,
direct-IP and port denial, DNS rebinding/private-address rejection, unique-destination accounting,
simulated network failure, exact secret grant binding, secret-use budget/refund behavior, raw
secret-export denial, provider-error sanitization, audit-token PID-reuse resistance, exact exec
denial, workspace/protected file authorization, fork/exec/exit attribution transitions, truncated
path denial, deadline failure, sequence gaps, dropped events, causal injection/egress, and audit
tampering.
Entitlement-dependent cases remain blocked until the real extensions exist; simulation and
broker-only mediation must not be reported as OS enforcement.

## Trust assumptions and limits

The macOS kernel, public Apple security frameworks, VIGIL's signed privileged components, and
human approval identity are trusted. Agent text, arguments, environment, claimed PID/session,
tool metadata, MCP schemas, DNS answers, and model output are attacker-controlled.

The current launcher is not a sandbox. It preserves evidence but cannot prevent a child from
bypassing semantic brokers. That exposure is the central reason Endpoint Security and Network
Extension are release gates rather than optional telemetry features.

All destructive tests must use disposable temporary roots, synthetic credentials, local test
servers, simulation, or isolated VMs. Never target `/`, the developer's home, or real secrets.
