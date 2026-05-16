#!/usr/bin/env bash
set -euo pipefail

# Build the Motoko backend canister into src/dfinsight_backend/.build/.
#
# Requires `mops` (npm i -g ic-mops) and a moc toolchain installed via
# `mops toolchain use moc`. Both are checked into mops.toml so a fresh
# clone only needs `mops install` once.
#
# Node 22+ note: `ic-mops` 1.x uses ESM features that don't exist in
# older Node runtimes. icp-cli's spawned subshell may default to
# whatever `which node` resolves to, which on macOS+nvm is often a
# stale v20. If nvm is available, source it and switch to a current
# Node before running `mops`.
#
# Skip in CI: GitHub Actions sets up Node 22 via `actions/setup-node`
# and installs `mops` globally against that Node version's prefix.
# Sourcing nvm here would switch PATH to a *different* Node version
# preinstalled on the runner, and the previously-installed `mops`
# would disappear from PATH — exiting the script silently under
# `set -e` before mops can complain. `${CI:-}` is set to `true` on
# GitHub-hosted runners; the empty-string default keeps `set -u`
# happy when CI is unset locally.
if [ -z "${CI:-}" ] && [ -s "${NVM_DIR:-$HOME/.nvm}/nvm.sh" ]; then
  # shellcheck disable=SC1091
  # `set -u` (pipefail above) trips on nvm.sh's unset-variable
  # references — e.g. on GitHub Actions runners where nvm is
  # preinstalled but several of its shell vars are undefined until
  # `nvm use` runs. Disable -u while sourcing, restore it after.
  set +u
  . "${NVM_DIR:-$HOME/.nvm}/nvm.sh"
  set -u
  # Prefer 24, fall back to whatever LTS is installed. `>/dev/null`
  # because nvm prints to stdout and we don't want it polluting the
  # build log.
  nvm use 24 >/dev/null 2>&1 || nvm use --lts >/dev/null 2>&1 || true
fi

cd "$(dirname "$0")/.."
cd src/dfinsight_backend

# `identity-attributes = "../../../.."` in mops.toml is a local-path
# dep. Two pieces of state can pin it to a now-invalid absolute path
# (e.g. a deleted git worktree), and moc then fails with M0012:
#
#   1. `mops.lock` — committed lockfile. mops bakes the absolute
#      resolved path into the `deps.identity-attributes` field, which
#      makes it machine-specific. If the lockfile has an absolute
#      path (anything starting with `/`), wipe it so mops regenerates
#      a fresh resolution against this checkout's mops.toml.
#   2. `.mops/identity-attributes` — cached resolution from a
#      previous install. Same machine-specificity story.
#
# Both are also gitignored at the repo root (mops.lock for this demo)
# but historical commits can still surface them; the defensive
# wipes below mean the build self-heals on any checkout.
if [ -f mops.lock ] && grep -qE '"identity-attributes": *"/' mops.lock; then
  echo "==> mops.lock pins identity-attributes to an absolute path — regenerating" >&2
  rm -f mops.lock
fi
rm -rf .mops/identity-attributes

mops install

mkdir -p .build

MOC=$(mops toolchain bin moc)
SOURCES=$(mops sources)

# `--release` strips debug info, `--public-metadata candid:service`
# embeds the .did so dapps can fetch it from the canister.
$MOC \
  $SOURCES \
  --release \
  --public-metadata candid:service \
  --idl \
  -o .build/dfinsight_backend.wasm \
  main.mo

# moc emits the .did next to the wasm — copy it where icp-cli expects.
if [ -f .build/dfinsight_backend.did ]; then
  : # already in place
elif [ -f .build/main.did ]; then
  mv .build/main.did .build/dfinsight_backend.did
fi
