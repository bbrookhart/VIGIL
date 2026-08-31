# Policy model

VIGIL has two policy engines, for two different jobs. Conflating them is the most common way to
misread this codebase.

## Portable policy — `vigil-policy`

Data-driven YAML bundles evaluated by `DeterministicPolicyEngine`, used by the portable
decision core and the Gateway.

- A bundle is an **unordered set**. Every matching rule folds through `Decision::combine`, which
  returns the more restrictive of two decisions. Rule order cannot change an outcome, and adding
  a rule can only restrict (ADR 0002, 0004).
- `default_effect` is `deny`. A request that matches nothing is denied.
- Validation refuses an empty rule set, duplicate ids, a condition-less matcher, `match_all` with
  `allow`, and `*` as a host pattern — the shapes that would silently disable enforcement.
- Matching uses a linear-time two-pointer globber, never regex, so a pattern cannot become a
  denial of service.
- Approver sets **intersect** and the shortest TTL wins when rules combine.

Cedar is not used; ADR 0016 records why, and the `PolicyEngine` trait leaves room for it.

## Local policy — `vigil-local`

A compiled-in evaluator for macOS sessions. It is *not* data-driven, and that is a deliberate
difference: these decisions bind to real filesystem resolution, a live session, and OS-level
concepts a YAML matcher cannot express.

Five profiles — `observe`, `developer-standard`, `developer-restricted`, `research`,
`untrusted-agent` — over the capability vocabulary in `CAPABILITY_MODEL.md`.

The ladder, in order:

1. **Ambient authority is refused outright.** `secret.export`, `system.persistence`,
   `system.privileged` are denied in every profile.
2. **Path resolution.** Through the real filesystem to the deepest existing ancestor, so a
   symlink cannot escape and `/work-evil` is not inside `/work`.
3. **Protected resources** deny independently of the workspace, categorised so a LaunchAgent
   write and an `~/.ssh` read are different findings.
4. **Observe profile** returns `OBSERVE` and enforces nothing. Nothing later in the pipeline may
   turn that into enforcement.
5. **Workspace containment** for reads and mutations.
6. **Git, process, network, and secret capabilities** by their own rules.
7. **Default deny** for everything outside a declared workspace.

Then the two session-state steps, in this order and no other: a lease may raise
`REQUIRE_APPROVAL` to `ALLOW`; risk degradation may only subtract. See ADR 0018.

## Testing policy before it is active

- `vigil policy validate <dir>` — parse and validate every shipped bundle.
- `vigil policy list <dir>` — print every rule with its effect, so a reviewer reads the whole
  posture at once.
- `vigil policy evaluate --profile … --action … --resource …` — a what-if against local policy,
  with no session and no side effects.
- `vigil simulate …` — the same question, persisted as replayable evidence.
- `cargo test -p vigil-policy --test policy_behaviour` — the shipped bundles are behaviourally
  tested, not merely parsed.

Every built-in policy has positive, negative, and boundary tests; for security policies the
negative tests are the point.
