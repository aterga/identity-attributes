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

# Each `icp` invocation may prompt for the identity password. Print
# what it's for *before* the prompt so the user knows which step is
# asking. Using stderr so the messages aren't swallowed by command
# substitution (BACKEND_ID=$(read_id ...)).
log() { echo "==> $*" >&2; }

log "[1/6] Creating canister: dfinsight_backend ($ENV)"
icp canister create dfinsight_backend  -e "$ENV" "${PASSTHROUGH[@]}"

log "[2/6] Creating canister: dfinsight_frontend ($ENV)"
icp canister create dfinsight_frontend -e "$ENV" "${PASSTHROUGH[@]}"

read_id() {
  # `icp canister status` prints "Canister Id: <id>" near the top.
  icp canister status "$1" -e "$ENV" "${PASSTHROUGH[@]}" \
    | awk '/^Canister Id:/ {print $3; exit}'
}

log "[3/6] Reading canister ids (status x2)"
BACKEND_ID=$(read_id dfinsight_backend)
FRONTEND_ID=$(read_id dfinsight_frontend)
log "      Backend  : $BACKEND_ID"
log "      Frontend : $FRONTEND_ID"

case "$ENV" in
  ic)
    ORIGIN="https://${FRONTEND_ID}.icp0.io"
    IC_HOST="https://icp-api.io"
    ;;
  local|*)
    ORIGIN="http://${FRONTEND_ID}.localhost:4943"
    IC_HOST="http://127.0.0.1:4943"
    ;;
esac

log "[4/6] Deploying both canisters (build + install + sync)"
log "      CANISTER_ID_DFINSIGHT_BACKEND=$BACKEND_ID"
log "      VITE_IC_HOST=$IC_HOST"
CANISTER_ID_DFINSIGHT_BACKEND="$BACKEND_ID" \
VITE_IC_HOST="$IC_HOST" \
  icp deploy -e "$ENV" "${PASSTHROUGH[@]}"

log "[5/6] Calling dfinsight_backend.setRpOrigin(\"$ORIGIN\")"
icp canister call dfinsight_backend setRpOrigin "(\"$ORIGIN\")" \
  -e "$ENV" "${PASSTHROUGH[@]}"

log "[6/6] Done."
log "      Frontend : $ORIGIN"
log "      Backend  : $BACKEND_ID"
