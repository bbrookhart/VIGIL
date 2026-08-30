# Secret broker model

The Phase 2 secret surface is an interface and simulator, not a native Keychain integration.
Its central invariant is that successful broker calls return a receipt, never credential bytes.

## Authority

Secret references are opaque, bounded `sec_...` handles. A trusted, precompiled grant binds all
of the following fields exactly:

```text
session profile + secret handle + use purpose + target
```

Supported purpose classes are Git authentication, HTTP authentication, and artifact signing.
These classes define the provider contract; they do not claim those end-to-end integrations are
already implemented. The agent cannot create or extend a grant through the broker. A future
`vigild` will load grants from signed policy and authenticate the IPC caller.

Authentication targets must be absolute HTTPS URLs without userinfo, query strings, or fragments;
signing targets must be lowercase SHA-256 digests. This keeps exact targets useful for policy and
prevents credentials or ambiguous URL components from entering evidence through configuration.

Metadata is available only when the profile already has at least one grant for the handle. It is
restricted to fixed enums: handle, secret kind, and supported purposes. Free-form labels and
provider descriptions are excluded because a provider could copy a credential into those fields.

## Provider boundary

`SecretProvider::perform` receives a structured authorized operation and returns only success or
failure. The broker never requests the underlying bytes. Provider error text is untrusted and is
collapsed to a low-cardinality error class before it reaches events or callers. Raw export is a
separate operation and always denies in the current local broker.

Provider use follows:

```text
validate session/request → exact grant → validate metadata → reserve budget
→ provider performs use → commit or refund → append content-free event
```

Each successful operation consumes `brokered_secret_uses`. Provider failure refunds the pending
reservation. If use succeeded but reconciliation fails, the reservation stays held in the safe
direction and the broker reports failure.

## Current limits

- `SimulatedSecretProvider` models metadata, success, failure, and invocation counts for CI, but
  deliberately contains no real secret material.
- No Keychain provider, native signing helper, authenticated Git/HTTP adapter, or CLI use command
  exists yet.
- Session IDs remain lookup keys rather than authenticated bearer credentials.
- Direct process access to environment variables, files, Keychain, or other credential sources
  remains bypassable until Endpoint Security, authenticated daemon IPC, and native providers
  exist.

The CLI reports `INTERFACE + SIMULATOR ONLY`; it never presents this phase as deployed secret
custody.
