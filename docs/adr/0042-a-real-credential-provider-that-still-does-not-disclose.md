# 0042 — A real credential provider that still does not disclose

Status: accepted
Date: 2026-08-30

## Context

ADR 0009 established that an agent should be able to *use* a credential without ever holding it.
The interface expressed that — `SecretProvider` splits `metadata` from `perform` — but the only
implementation was a simulator. `vigil status` reported `INTERFACE_AND_SIMULATOR_ONLY`, there was no
route to a credential a user actually has, and `FAIL_CLOSED_MATRIX.md` listed the native provider as
not built. A separation of concerns with nothing behind it is a design, not a control.

## Decision

`KeychainSecretProvider` reads secrets from the macOS Keychain through `/usr/bin/security`.

The split between the two operations is the whole point, and it is enforced by the *flag*, not by
discipline:

- `metadata` runs `security find-generic-password` **without** `-w`. The secret is not in the
  output at all, so there is nothing to accidentally log, serialize or return.
- `perform` reads the value and hands it to the operation that needs it.

Specifics that carry weight:

- **The credential reaches `git` through `GIT_ASKPASS`, pointing at a helper that invokes
  `security` itself.** The value travels from the Keychain into `git` directly. VIGIL never writes
  it to a file, never puts it in `argv`, and never holds it across the call. The helper script on
  disk contains the *lookup*, never the secret — asserted by a test, because that file is the one
  place where getting this wrong would leave the credential sitting on disk.
- **Purposes are derived from the kind, never read from the item.** A Keychain entry cannot widen
  its own authority by declaring extra purposes, and `perform` re-checks the pairing even though
  the broker already checked the grant: a signing key pressed into service as a git credential is
  refused twice.
- **Unimplemented purposes return an error.** HTTP authentication and artifact signing are not
  built. Returning `Ok` would record a use that never happened, and writing an HTTP client here
  would put a credential on a code path nothing has reviewed.
- **An item without a VIGIL kind label is refused.** An arbitrary Keychain entry the user happens
  to own is not a VIGIL secret, and guessing a kind for it would bring unrelated credentials into
  the broker's reach.
- **The CLI denies by default.** `vigil secrets metadata` without `--grants` refuses every request.
  Making the policy something a caller opts into would be backwards.

Access is through `security` rather than the Security framework because this crate is
`#![forbid(unsafe_code)]` and `SecKeychain*` is FFI — the same reasoning as ADR 0041's use of `ps`.

## Consequences

The matrix row changes from "not built" to a narrower and truer statement: the provider is real,
and what is missing is *purposes*, not the provider.

Non-disclosure is tested rather than asserted. One test drives the whole path end to end with a
real secret in a throwaway keychain and checks it appears in neither the output nor the event
store; another runs the metadata lookup and asserts the raw `security` output contains no secret,
which guards the flag rather than the parse. Adding `-w` to the metadata path would make the value
available to a caller that only asked what kind of thing it was, and no assertion on the parsed
struct would notice.

Tests use a throwaway keychain created with `security create-keychain`, so they never touch the
login keychain and never prompt. That is also what makes them run in CI.

**What is proven and what is not.** The tests prove the metadata path does not disclose, that the
askpass helper carries no secret, and that purpose and kind are enforced. They do **not** prove a
successful authenticated fetch: that needs a reachable remote and a real credential, which no test
here has. The wiring is exercised against an unreachable target, so a broken `GIT_ASKPASS` contract
would show up as a failure to authenticate rather than as a silent pass.

A locked keychain prompts, and that prompt is the user deciding — but it means `perform` can block
on a human. The call is bounded, and a timeout is reported as a failure rather than as a denial,
because "the user did not answer" and "the credential is not permitted" are different facts.

This does not satisfy invariant 3. With no `vigild`, an agent running as the user can invoke
`security` directly and read the same Keychain items. What this changes is that VIGIL's *own* path
does not disclose, and every use through it is recorded.
