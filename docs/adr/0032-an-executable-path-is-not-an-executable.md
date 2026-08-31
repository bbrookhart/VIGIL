# ADR 0032 — An executable path is not an executable

**Status:** Accepted  
**Date:** 2026-08-30

## Context

§17 says plainly: "Do not assume executable path is sufficient identity. Consider: path, code
signature, hash when appropriate." §10 says the same about provenance — build a stable identity
from immutable properties rather than reusable ones.

The process broker validated an absolute canonical path, checked the exec bit, rejected set-id
binaries — and then spawned by name. Two things followed from that.

**The provenance graph did not record what ran.** `ProcessNode.executable_sha256` has been in the
schema since the graph was built, and both call sites passed `None`. Every node recorded a path and
nothing else, so "which binary was that?" had no answer, which is precisely the question a
provenance graph exists to answer.

**The path could change between validation and execution.** `Command::spawn` resolves the name
again. Everything the broker checked — canonical path, exec bit, no set-id, class allowlist —
applied to whatever the name referred to at validation time, not to what actually ran.

## Decision

Identify the executable, not the name.

At validation the broker takes the object's device and inode and, when the file is at most 64 MiB,
hashes its contents. Immediately before `spawn` it re-checks that the name still refers to that
object. A mismatch refuses the execution, records `VIGIL-L033`, and loads the process-anomaly
dimension.

The hash goes into the provenance node, so the graph now records *what ran* rather than where it
was. `vigil run` does the same for the child that roots a session's lineage.

The 64 MiB bound exists because hashing is per-execution work on the broker's path and the enforced
profiles permit only small system utilities. Above it the object is still identified by device and
inode — just not by content.

## Consequences

Verified end to end: a brokered `/bin/echo` records a hash identical to `shasum -a 256`, and the
root of a `vigil run` session is identified the same way. Two unit tests assert that identical
bytes at two paths share a content hash but not an object identity, and that replacing a binary
after validation — or removing it — is reported as changed.

`VIGIL-L033` is `CRITICAL`/`HIGH` at weight 60. High confidence because a binary that changes
identity in the moment between being validated and being executed is not an accident. Weight 60
contains rather than quarantines, because a package upgrade could in principle land in that window.

### The window this closes

The same one as ADR 0031, in the same way and with the same limit: **validate-to-spawn is narrowed
and made detectable, not eliminated.** A swap that lands between the final check and the kernel's
own resolution still succeeds. Only an Endpoint Security client, which reports the image the kernel
actually executed, closes it.

### What is still missing

Code signature is not checked. §17 lists it alongside path and hash, and macOS makes it available
through `SecStaticCodeCheckValidity` — but that is a native API, and this crate is portable Rust
with no Apple framework access by design (ADR 0010). Signing identity belongs with the native
adapter, which already checks code requirements for its XPC peers. A hash tells you the bytes were
the same as last time; a signature tells you who produced them, and VIGIL currently has only the
first.
