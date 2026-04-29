#!/usr/bin/env bash
set -euo pipefail

# Two-pass deploy that wires the backend canister id into the frontend
# bundle, then calls `setRpOrigin` on the backend with the frontend URL.
#
# Usage:
#   scripts/deploy.sh                          # mainnet (default)
#   scripts/deploy.sh -e local                 # local replica
#   scripts/deploy.sh -e ic --identity arshavir
#
# Why this script exists: icp-cli builds canisters BEFORE creating them,
# so on a one-shot `icp deploy -e ic` the frontend bundle is built with
# `CANISTER_ID_DFINSIGHT_BACKEND` unset and `config.ts` falls back to a
# stale local id. We work around that by minting both canister ids up
# front, then handing them to `icp deploy` via the env. The
# `setRpOrigin` call is needed because `rpOrigin` is a stable `var`
# inside the actor — it has to be set once after the frontend canister
# id is known so the Authorization-tier verify accepts admin sign-ins.

ENV=ic
PASSTHROUGH=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -e|--environment) ENV="$2"; shift 2;;
    *) PASSTHROUGH+=("$1"); shift;;
  esac
done

cd "$(dirname "$0")/.."

echo "[1/4] Pre-creating canisters on '$ENV'..."
icp canister create dfinsight_backend  -e "$ENV" "${PASSTHROUGH[@]}"
icp canister create dfinsight_frontend -e "$ENV" "${PASSTHROUGH[@]}"

read_id() {
  # `icp canister status` prints "Canister Id: <id>" near the top.
  icp canister status "$1" -e "$ENV" "${PASSTHROUGH[@]}" \
    | awk '/^Canister Id:/ {print $3; exit}'
}

BACKEND_ID=$(read_id dfinsight_backend)
FRONTEND_ID=$(read_id dfinsight_frontend)

echo "[2/4] Backend  : $BACKEND_ID"
echo "      Frontend : $FRONTEND_ID"

case "$ENV" in
  ic)    ORIGIN="https://${FRONTEND_ID}.icp0.io" ;;
  local) ORIGIN="http://${FRONTEND_ID}.localhost:4943" ;;
  *)     ORIGIN="http://${FRONTEND_ID}.localhost:4943" ;;
esac

echo "[3/4] Deploying with CANISTER_ID_DFINSIGHT_BACKEND=$BACKEND_ID..."
CANISTER_ID_DFINSIGHT_BACKEND="$BACKEND_ID" \
  icp deploy -e "$ENV" "${PASSTHROUGH[@]}"

echo "[4/4] Setting rpOrigin to $ORIGIN..."
icp canister call dfinsight_backend setRpOrigin "(\"$ORIGIN\")" \
  -e "$ENV" "${PASSTHROUGH[@]}"

echo ""
echo "Done."
echo "  Frontend : $ORIGIN"
echo "  Backend  : $BACKEND_ID"
