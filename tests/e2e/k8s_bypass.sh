#!/usr/bin/env bash
#
# The non-bypassability proof.
#
# VIGIL's threat model lists one gap it cannot close in application code: "bypass by not
# calling VIGIL at all". Credential custody gets most of the way — the agent holds no API
# keys — but an agent with unrestricted network access could still reach an internal service
# that trusts the network. The NetworkPolicy in deploy/helm/vigil closes it, and this script
# is what turns that from an assertion into a tested control.
#
# Deployment network-boundary test: gateway reachability, unauthenticated refusal,
# direct protected-tool denial, and a positive tool-reachability control.
# This does not prove authenticated capability execution through the deployed HTTP service.
# The in-process positive/negative capability controls live in vigil-core's end_to_end suite.
# Do not describe this script alone as complete mediation or production authentication proof.
#
# Requires: kind, kubectl, helm, docker. Run via `make test-k8s`.
set -euo pipefail

CLUSTER="${CLUSTER:-vigil-bypass}"
NS_VIGIL="${NS_VIGIL:-vigil}"
NS_AGENTS="${NS_AGENTS:-agents}"
IMAGE="${IMAGE:-vigil:e2e}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

log()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$*"; exit 1; }

cleanup() {
  if [[ -n "${KEYDIR:-}" ]]; then rm -rf -- "$KEYDIR"; fi
  if [[ "${KEEP_CLUSTER:-0}" != "1" ]]; then
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------- cluster

log "Creating cluster (CNI with NetworkPolicy support)"
# The default kind CNI does NOT enforce NetworkPolicy. Using it would make this script
# report success while enforcing nothing — the precise failure mode the script exists to
# rule out — so the CNI is disabled and Calico installed instead.
cat <<'EOF' | kind create cluster --name "$CLUSTER" --config=- >/dev/null
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: "192.168.0.0/16"
EOF

kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml >/dev/null
kubectl -n kube-system rollout status daemonset/calico-node --timeout=300s >/dev/null
pass "cluster ready with a policy-enforcing CNI"

# ---------------------------------------------------------------- build & load

log "Building and loading images"
docker build -t "$IMAGE" -f "$ROOT/deploy/docker/Dockerfile" "$ROOT" >/dev/null
kind load docker-image "$IMAGE" --name "$CLUSTER" >/dev/null
pass "image loaded"

kubectl create namespace "$NS_VIGIL" >/dev/null
kubectl create namespace "$NS_AGENTS" >/dev/null
# The NetworkPolicy selects namespaces by this label; without it the policy matches nothing.
kubectl label namespace "$NS_AGENTS" kubernetes.io/metadata.name="$NS_AGENTS" --overwrite >/dev/null
kubectl label namespace "$NS_VIGIL" kubernetes.io/metadata.name="$NS_VIGIL" --overwrite >/dev/null

# ---------------------------------------------------------------- keys & policies

log "Generating signing keys and installing policy"
KEYDIR="$(mktemp -d)"
cargo run -q -p vigil-cli --bin vigil -- keys generate --out "$KEYDIR" >/dev/null
CAP_PUB="$(cargo run -q -p vigil-cli --bin vigil -- keys public "$KEYDIR/capability.key")"

kubectl -n "$NS_VIGIL" create secret generic vigil-signing-keys \
  --from-file=capability.key="$KEYDIR/capability.key" \
  --from-file=approval.key="$KEYDIR/approval.key" \
  --from-file=audit.key="$KEYDIR/audit.key" >/dev/null
pass "keys and policies installed (Gateway receives only the public half)"

# ---------------------------------------------------------------- deploy

log "Installing the chart"
helm install vigil "$ROOT/deploy/helm/vigil" \
  --namespace "$NS_VIGIL" \
  --set tenant=acme \
  --set policies.useImageDefaults=true \
  --set image.registry=docker.io --set image.repository=library/vigil --set image.tag=e2e \
  --set image.pullPolicy=Never \
  --set gateway.capabilityPublicKey="$CAP_PUB" \
  --set networkPolicy.agentNamespaces="{$NS_AGENTS}" \
  --set auth.peerIdentity.trustedPeers="{10.0.0.1}" \
  --wait --timeout 300s >/dev/null || {
    kubectl -n "$NS_VIGIL" get pods -o wide
    kubectl -n "$NS_VIGIL" get events --sort-by=.lastTimestamp
    # Logs describe startup errors; never dump Secret objects or environment values.
    kubectl -n "$NS_VIGIL" logs -l app.kubernetes.io/component=core --tail=40 || true
    kubectl -n "$NS_VIGIL" logs -l app.kubernetes.io/component=gateway --tail=40 || true
    fail "VIGIL did not become ready"
  }
pass "VIGIL deployed"

log "Deploying the mock protected tool and the agent"
kubectl -n "$NS_VIGIL" apply -f - <<'EOF' >/dev/null
apiVersion: v1
kind: Service
metadata: { name: mock-tool, labels: { app: mock-tool } }
spec:
  selector: { app: mock-tool }
  ports: [{ port: 80, targetPort: 5678 }]
---
apiVersion: v1
kind: Pod
metadata: { name: mock-tool, labels: { app: mock-tool } }
spec:
  containers:
    - name: tool
      image: hashicorp/http-echo:1.0
      args: ["-listen=:5678", "-text=SIDE EFFECT EXECUTED"]
      ports: [{ containerPort: 5678 }]
      readinessProbe:
        httpGet: { path: /, port: 5678 }
        periodSeconds: 1
        failureThreshold: 30
EOF

kubectl -n "$NS_AGENTS" apply -f - <<'EOF' >/dev/null
apiVersion: v1
kind: Pod
metadata: { name: agent, labels: { app: agent } }
spec:
  containers:
    - name: agent
      image: curlimages/curl:8.10.1
      command: ["sleep", "3600"]
EOF

kubectl -n "$NS_VIGIL" wait --for=condition=Ready pod/mock-tool --timeout=120s >/dev/null || {
  kubectl -n "$NS_VIGIL" logs mock-tool --tail=40 || true
  fail "mock tool did not become HTTP-ready"
}
kubectl -n "$NS_AGENTS" wait --for=condition=Ready pod/agent --timeout=120s >/dev/null
pass "mock tool and agent running"

source "$ROOT/tests/e2e/http_probe.sh"
agent_curl() {
  probe_http kubectl -n "$NS_AGENTS" exec agent -- \
    curl -s -o /dev/null -w '%{http_code}' --max-time 8 "$@"
}

# ---------------------------------------------------------------- the assertions

log "Assertion 1 — the agent can reach VIGIL Gateway"
code="$(agent_curl "http://vigil-vigil-gateway.$NS_VIGIL.svc.cluster.local:8081/healthz")"
[[ "$code" == "200" ]] || fail "the agent cannot reach the Gateway (HTTP $code); the deployment is broken, not secure"
pass "agent → gateway reachable (HTTP $code)"

log "Assertion 2 — the Gateway refuses an action with no capability"
code="$(agent_curl -X POST -H 'content-type: application/json' -d '{}' \
  "http://vigil-vigil-gateway.$NS_VIGIL.svc.cluster.local:8081/v1/execute")"
[[ "$code" == "401" || "$code" == "403" ]] || fail "expected 401/403 without a capability, got $code"
pass "gateway refused an uncapability'd action (HTTP $code)"

log "Assertion 3 — the agent CANNOT reach the protected tool directly"
# The load-bearing assertion. A NetworkPolicy drop manifests as a timeout, so curl reports
# 000 rather than a status code. Anything else means the boundary is not enforced.
tool_ip="$(kubectl -n "$NS_VIGIL" get service mock-tool -o jsonpath='{.spec.clusterIP}')"
[[ -n "$tool_ip" ]] || fail "mock-tool has no ClusterIP"
code="$(agent_curl "http://$tool_ip:80/")"
if [[ "$code" == "200" ]]; then
  fail "THE AGENT REACHED THE PROTECTED TOOL DIRECTLY. VIGIL is bypassable in this deployment."
fi
[[ "$code" == "000" ]] || fail "expected the connection to be dropped, got HTTP $code"
pass "agent → protected tool BLOCKED by NetworkPolicy (connection dropped)"

log "Assertion 4 — the block is the policy, not a broken cluster"
# Rules out a false pass: if the mock tool were simply unreachable by everyone, assertion 3
# would succeed for the wrong reason. A pod inside the VIGIL namespace must still reach it.
kubectl -n "$NS_VIGIL" run prober --restart=Never --image=curlimages/curl:8.10.1 \
  --command -- sleep 300 >/dev/null
kubectl -n "$NS_VIGIL" wait --for=condition=Ready pod/prober --timeout=120s >/dev/null
inside="$(probe_http kubectl -n "$NS_VIGIL" exec prober -- \
  curl -s -o /dev/null -w '%{http_code}' --max-time 8 "http://$tool_ip:80/")"
[[ "$inside" == "200" ]] || fail "the mock tool is unreachable even from inside VIGIL's namespace (HTTP $inside); assertion 3 passed for the wrong reason"
pass "the tool IS reachable from inside VIGIL's namespace (HTTP $inside) — the block is the policy"

log "RESULT"
echo "  The protected tool is reachable from VIGIL and unreachable from the agent."
echo "  Network isolation passed for this deployment; authenticated capability execution is a separate gate."
