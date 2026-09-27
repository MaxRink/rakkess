#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CLUSTER=${KIND_CLUSTER:-rakkess-e2e}
KIND_NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5}
BIN=${RAKKESS_BIN:-${ROOT}/out/rakkess-e2e}
OPERATOR_IMAGE=auth-operator:rakkess-e2e-233d421
: "${AUTH_OPERATOR_DIR:?point AUTH_OPERATOR_DIR to the pinned auth-operator checkout}"
for command in kind kubectl helm docker jq; do command -v "$command" >/dev/null; done
test -x "$BIN"
test "$(git -C "$AUTH_OPERATOR_DIR" rev-parse HEAD)" = 233d42191da159cbe21bf340829ef3f4be9a3ec5
test -z "$(git -C "$AUTH_OPERATOR_DIR" status --porcelain)"
if kind get clusters 2>/dev/null | grep -Fxq "$CLUSTER"; then
  echo "refusing to touch existing Kind cluster $CLUSTER" >&2
  exit 1
fi
WORK=$(mktemp -d)
export KUBECONFIG="$WORK/kubeconfig"
cleanup() {
  local status=$?
  if (( status != 0 )); then
    kubectl get pods -A >&2 || true
    kubectl -n auth-operator-system logs deployment/auth-operator-controller-manager --tail=80 >&2 || true
    cat "$WORK"/*.json >&2 2>/dev/null || true
  fi
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
kind create cluster --name "$CLUSTER" --image "$KIND_NODE_IMAGE" --kubeconfig "$KUBECONFIG"
kubectl apply -f "$ROOT/e2e/fixtures/rbac.yaml"
kubectl wait --for=condition=Ready node --all --timeout=120s

assert_cell() {
  local output=$1 resource=$2 expected=$3
  if ! awk -v resource="$resource" -v expected="$expected" '$1 == resource && $NF == expected { found = 1 } END { exit !found }' <<<"$output"; then
    printf 'expected %s=%s in:\n%s\n' "$resource" "$expected" "$output" >&2
    return 1
  fi
}
wait_for() {
  for _ in $(seq 1 90); do
    if "$@"; then return 0; fi
    sleep 2
  done
  echo "timed out: $*" >&2
  return 1
}
has_rules() { kubectl get clusterrole "$1" -o json | jq -e 'any(.rules[]?; any(.resources[]?; . == "configmaps"))' >/dev/null; }
matrix() { "$BIN" --output ascii-table --verbs list "$@"; }
wait_for has_rules aggregate-parent
assert_cell "$(matrix -n rakkess-e2e --sa rakkess-e2e:reader)" pods yes
assert_cell "$(matrix --sa rakkess-e2e:reader)" pods no
assert_cell "$(matrix --sa rakkess-e2e:writer)" configmaps yes
assert_cell "$(matrix -n rakkess-e2e --sa rakkess-e2e:reader --diff-with=sa=rakkess-e2e:writer)" configmaps yes
assert_cell "$(matrix -n rakkess-e2e-open --sa rakkess-e2e:reader)" configmaps yes
kubectl -n rakkess-e2e-open delete rolebinding native-sa-groups
assert_cell "$(matrix -n rakkess-e2e-open --sa rakkess-e2e:reader)" configmaps no
assert_cell "$(matrix -n rakkess-e2e --as e2e-user --as-group rakkess-e2e-readers)" pods yes
assert_cell "$(matrix -n rakkess-e2e --as e2e-user --as-group rakkess-e2e-denied)" pods no
assert_cell "$(matrix -n rakkess-e2e --as e2e-user --as-group rakkess-e2e-readers --diff-with=as-group=rakkess-e2e-denied)" pods no
assert_cell "$(matrix -n rakkess-e2e --as e2e-user --as-group rakkess-e2e-denied --diff-with=as-group=rakkess-e2e-readers --diff-with=as-group=additional-group)" pods yes

# Build the immutable real operator source; --load also supports container builders.
docker build --load -t "$OPERATOR_IMAGE" "$AUTH_OPERATOR_DIR"
kind load docker-image "$OPERATOR_IMAGE" --name "$CLUSTER"
helm upgrade --install auth-operator "$AUTH_OPERATOR_DIR/chart/auth-operator" \
  --namespace auth-operator-system --create-namespace \
  --set image.repository=auth-operator --set image.tag=rakkess-e2e-233d421 \
  --set image.digest= --set image.pullPolicy=IfNotPresent --set webhookServer.replicas=1
kubectl -n auth-operator-system rollout status deployment/auth-operator-controller-manager --timeout=240s
kubectl -n auth-operator-system rollout status deployment/auth-operator-webhook-server --timeout=240s
kubectl apply -f "$ROOT/e2e/fixtures/auth-operator.yaml"
wait_for has_rules generated-aggregate
has_binding() {
  kubectl -n "$1" get rolebindings -l app.kubernetes.io/managed-by=auth-operator -o json |
    jq -e 'any(.items[]; .roleRef.kind == "ClusterRole" and .roleRef.name == "generated-aggregate" and any(.subjects[]; .kind == "ServiceAccount" and .namespace == "rakkess-e2e" and .name == "operator-reader"))' >/dev/null
}
wait_for has_binding rakkess-e2e
wait_for has_binding rakkess-e2e-open
wait_for kubectl -n rakkess-e2e get role/generated-reader
for ns in rakkess-e2e-protected rakkess-e2e-denied; do
  if has_binding "$ns"; then echo "unexpected generated binding in $ns" >&2; exit 1; fi
  assert_cell "$(matrix -n "$ns" --sa rakkess-e2e:operator-reader)" configmaps no
done
assert_cell "$(matrix --sa rakkess-e2e:operator-reader)" configmaps no
assert_cell "$(matrix --sa rakkess-e2e:operator-reader)" nodes no
for ns in rakkess-e2e rakkess-e2e-open; do
  matrix -n "$ns" --sa rakkess-e2e:operator-reader --auth-operator >"$WORK/table" 2>"$WORK/report.json"
  assert_cell "$(cat "$WORK/table")" configmaps yes
  jq -e --arg ns "$ns" '.authOperator.original |
    .complete == true and .advisory == true and .namespace == $ns and
    .username == "system:serviceaccount:rakkess-e2e:operator-reader" and
    (.groups | index("system:serviceaccounts:rakkess-e2e") != null) and
    any(.origins[]; .kind == "BindDefinition" and .name == "selector-reader" and .queriedNamespaceMatch == true and
      (.matchingNamespaces | sort) == ["rakkess-e2e", "rakkess-e2e-open"] and
      any(.generated[]; .namespace == $ns and .roleRef.name == "generated-aggregate")) and
    any(.origins[]; .kind == "RoleDefinition" and .name == "generated-aggregate") and
    any(.roles[]; .name == "generated-aggregate" and .aggregateSources == ["aggregate-reader"])' "$WORK/report.json" >/dev/null
 done
matrix -n rakkess-e2e --sa rakkess-e2e:operator-reader --auth-operator --diff-with=sa=rakkess-e2e:reader >"$WORK/table" 2>"$WORK/diff.json"
assert_cell "$(cat "$WORK/table")" configmaps no
jq -e '.authOperator.original.complete == true and .authOperator.modified.complete == false and (.authOperator.modified.errors | length > 0)' "$WORK/diff.json" >/dev/null
matrix -n rakkess-e2e --sa rakkess-e2e:reader --auth-operator >"$WORK/table" 2>"$WORK/partial.json"
assert_cell "$(cat "$WORK/table")" pods yes
jq -e '.authOperator.original | .complete == false and .advisory == true and (.errors | length > 0)' "$WORK/partial.json" >/dev/null
# Recheck exclusions after positive reconciliation and provenance have completed.
for ns in rakkess-e2e-protected rakkess-e2e-denied; do
  if has_binding "$ns"; then echo "unexpected generated binding in $ns" >&2; exit 1; fi
  assert_cell "$(matrix -n "$ns" --sa rakkess-e2e:operator-reader)" configmaps no
done
echo "PASS: native SSAR, SA groups, group gain/loss, operator reconciliation, selectors, aggregation and partial provenance"
