# ADR 0026 — Git configuration is a code-execution surface

**Status:** Accepted  
**Date:** 2026-08-30

## Context

Git is the highest-leverage tool a coding agent touches, and §11 lists nine `git.*` capabilities.
The obvious way to add Git support — shell out to `git` with the requested subcommand — would
have quietly handed the agent the arbitrary code execution that ADR 0007's process broker exists
to refuse.

The reason is that **Git configuration executes programs**. A partial list of keys whose value
Git runs as a command: `core.pager`, `core.editor`, `core.sshCommand`, `core.hooksPath`,
`credential.helper`, `diff.*.textconv`, `filter.*.clean` and `.smudge`, `sequence.editor`,
`uploadpack.packObjectsHook`, and every `alias.*`. Hooks in `.git/hooks` run on commit and push.

An agent that can write files in a workspace can write `.git/config` and `.git/hooks/pre-commit`.
So in a repository the agent controls, a plain `git status` is a code-execution primitive — and it
is reached through a capability that sounds like the most harmless one in the vocabulary.

## Decision

### Neutralise unconditionally; never check-then-run

`hardened_command` builds every invocation with `-c` overrides for each execution-bearing key.
Command-line `-c` takes precedence over repository, global, and system configuration, which is
what makes this work.

The overrides are applied **unconditionally**, not after inspecting the repository. A
check-then-run sequence is a race against a file the agent can rewrite between the check and the
run. Framing it as "the set we always override" also means the gap is a key we did not think of,
rather than every key a denylist failed to match.

Alongside that: `core.hooksPath` points at a freshly created empty directory, so no hook exists to
run; `GIT_CONFIG_NOSYSTEM=1` and a redirected `HOME` remove `/etc/gitconfig` and `~/.gitconfig`;
the environment is otherwise cleared; `GIT_TERMINAL_PROMPT=0` and empty askpass variables mean Git
cannot stop for input or reach a credential helper.

A live test proves this, with a control. One repository is rigged with five executable config keys
and a `pre-commit` hook, and five broker operations run against it without the payload firing. The
control then runs `git commit` naively against the *same* repository and asserts the marker **does**
appear — so the first test proves the hardening works rather than proving the payload was inert.

### No caller-supplied value may begin with `-`

A branch named `--upload-pack=…`, a path named `-c`, or a message starting with `-` would be parsed
by Git as an option. `--` separators help for paths but not every position, so a leading `-` is
refused outright, in every field.

### Capabilities are split by what they actually reach

- `git.status`, `git.read`, `git.stage` — local, permitted.
- `git.commit` — a workspace mutation; permitted except for `untrusted-agent`, which needs approval.
- `git.push` — the point at which workspace content leaves the machine. Approval-bound, *and* the
  remote's host goes through the same network destination policy as any other egress. Being
  permitted to push is not permission to push anywhere. The lease binds `git:push:<remote>:<branch>`,
  so approving a push to `origin/main` authorizes nothing else.
- `git.force_push` — denied in every enforcing profile. It discards history that already exists on
  the remote, including other people's, and no approval widens it.
- `git.config`, `git.remote_modify` — denied. These change what every *later* Git command does, and
  several config keys are the execution surface above.

### Calibration: finding neutralised config is not an incident

The first draft rated `VIGIL-L021` `CRITICAL` at weight 60, which contained a session the moment it
ran `git status` in a rigged repository. Writing the live test surfaced that as wrong twice over.

First, VIGIL *neutralised* the configuration — nothing executed, so nothing happened. Second, the
keys involved are overwhelmingly benign in practice: `alias.*` is universal, `credential.helper` is
how people authenticate, and `filter.*` is set by git-lfs in a large fraction of real repositories.
A rule that contains a session on `git status` in any LFS repository is a rule that gets turned off
within a day, taking the useful findings with it.

It is now `MEDIUM`/`HIGH` at weight 10 — below the elevation threshold, so it never changes a
session's standing alone, while still corroborating if something else goes wrong. It is also
reported **once per distinct key set per session** rather than once per command: a rigged
repository is a standing property, and repeating the finding across five commands would accumulate
risk until an ordinary repository looked alarming.

Config *values* are never recorded. The value is the command that would have run and may embed a
token; the key name says enough to investigate.

### The subprocess wait is bounded

`GIT_TERMINAL_PROMPT=0` stops Git waiting on a person, but a network operation can still hang. The
wait has a 30-second deadline after which the child is killed, and output is drained on threads so
a child filling a pipe cannot deadlock a parent that is only polling for exit.

## Consequences

Phase 2's broker set is complete apart from the shell broker, which ADR 0007 deliberately excludes.
Prompt Demo 1 — an agent that reads source, edits the workspace, and interacts with GitHub — is now
expressible entirely through brokered capabilities.

### What this does not do

It runs the real `git` binary and does not sandbox it: Git can still read any file the user can.
This broker bounds *which Git operations happen and under what configuration*. It does not bound
what the resulting process could do if Git itself were compromised, and it does not observe a
`git` invoked outside the broker — which the process broker denies, but which an unmediated process
could still perform.
