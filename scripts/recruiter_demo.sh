#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
demo_root="$(mktemp -d)"
trap 'rm -rf "$demo_root"' EXIT
workspace="$demo_root/workspace"
database="$demo_root/vigil.db"
mkdir -p "$workspace"

vigil() {
  cargo run -q -p vigil-cli --bin vigil -- --state-db "$database" "$@"
}

section() {
  printf '\n\033[1;36m%s\033[0m\n' "$1"
}

cd "$repo_root"
section "1/4 Safe brokered action"
session_json="$(vigil session start --profile developer-standard --workspace "$workspace" --json)"
session_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["session_id"])' <<<"$session_json")"
printf 'reviewable side effect\n' | vigil fs write "$session_id" result.txt
printf 'Broker read: '
vigil fs read "$session_id" result.txt

section "2/4 Protected-resource decision"
vigil simulate --profile developer-standard --workspace "$workspace" \
  --action fs.read --resource "${HOME}/.ssh/id_ed25519" --json || true

section "3/4 Indirect prompt-injection interception"
cargo run -q -p vigil-core --example demo

section "4/4 Human approval mints one bounded lease"
vigil process exec "$session_id" --program /usr/bin/uname --discard-output || true
approval_id="$(vigil approvals list --session "$session_id" --status pending --json \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["approval_id"])')"
vigil approvals grant "$approval_id" --approver recruiter-demo --max-uses 1 --json
vigil process exec "$session_id" --program /usr/bin/uname --discard-output

section "Evidence"
vigil session budget "$session_id" --json
printf '\nDemo workspace was temporary; no host credential was read or modified.\n'
