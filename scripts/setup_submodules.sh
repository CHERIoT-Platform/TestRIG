#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
#
# Bring the TestRIG working tree into the exact state the CHERIoT Sail
# RVFI patch expects:
#
#   TestRIG (top)                         dii-read-from-file
#   └── riscv-implementations/
#       └── cheriot-sail                  dii-read-from-file
#           └── sail-riscv  (nested)      cheriot-dii-read-from-file
#
# Safe to re-run. Idempotent. Initialises submodules first if they're
# empty, then checks out the right branches and pulls --ff-only.
#
# Run before `docker compose build` (or use scripts/docker_build.sh
# which wraps both steps).

set -euo pipefail

# --- locate TestRIG root --------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT}"

# Branch policy: edit here if upstream renames anything.
TESTRIG_BRANCH="dii-read-from-file"
CHERIOT_SAIL_BRANCH="dii-read-from-file"
SAIL_RISCV_BRANCH="cheriot-dii-read-from-file"

CHERIOT_SAIL="riscv-implementations/cheriot-sail"
NESTED_SAIL_RISCV="${CHERIOT_SAIL}/sail-riscv"

# --- helpers --------------------------------------------------------------
log()  { printf '\n\033[1;34m== %s ==\033[0m\n' "$*"; }
ok()   { printf '\033[0;32m  ok\033[0m %s\n' "$*"; }
warn() { printf '\033[0;33m  warn\033[0m %s\n' "$*"; }
die()  { printf '\033[0;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# Check out a branch and pull --ff-only. If the branch exists locally
# already, switch to it; otherwise create a tracking branch from
# origin/<branch>. Fails loud if the remote branch doesn't exist.
checkout_branch() {
  local dir="$1" branch="$2"
  ( cd "${dir}" \
    && git fetch --tags origin "${branch}" 2>/dev/null \
    && if git show-ref --verify --quiet "refs/heads/${branch}"; then
         git switch "${branch}"
       else
         git switch -c "${branch}" --track "origin/${branch}"
       fi \
    && git pull --ff-only origin "${branch}"
  ) || die "failed to bring ${dir} to branch ${branch}
  Check: does the remote branch 'origin/${branch}' exist?"
}

# --- 1. TestRIG itself ----------------------------------------------------
log "TestRIG → ${TESTRIG_BRANCH}"
current="$(git branch --show-current 2>/dev/null || echo '')"
if [[ "${current}" != "${TESTRIG_BRANCH}" ]]; then
  warn "TestRIG is on '${current}', expected '${TESTRIG_BRANCH}'."
  warn "Not auto-switching (it has your local edits). To switch:"
  warn "    git switch ${TESTRIG_BRANCH}    # then re-run this script"
else
  ok "TestRIG on ${TESTRIG_BRANCH}"
fi

# --- 2. Initialise submodules if empty ------------------------------------
# Check if cheriot-sail is populated. An empty submodule is just an
# empty dir (no .git file/dir inside it).
log "Submodule init"
if [[ ! -e "${CHERIOT_SAIL}/.git" ]]; then
  ok "cheriot-sail not initialised — running git submodule update --init --recursive"
  git submodule update --init --recursive
else
  ok "submodules already initialised"
fi

# --- 3. cheriot-sail branch -----------------------------------------------
log "cheriot-sail → ${CHERIOT_SAIL_BRANCH}"
checkout_branch "${CHERIOT_SAIL}" "${CHERIOT_SAIL_BRANCH}"
ok "cheriot-sail on ${CHERIOT_SAIL_BRANCH} ($(cd "${CHERIOT_SAIL}" && git rev-parse --short HEAD))"

# --- 4. nested sail-riscv branch ------------------------------------------
# Branch checkout of cheriot-sail may move the nested submodule pointer,
# so re-init/update first.
log "cheriot-sail/sail-riscv → ${SAIL_RISCV_BRANCH}"
( cd "${CHERIOT_SAIL}" && git submodule update --init --recursive ) \
  || die "failed to init nested submodules inside cheriot-sail"
checkout_branch "${NESTED_SAIL_RISCV}" "${SAIL_RISCV_BRANCH}"
ok "sail-riscv on ${SAIL_RISCV_BRANCH} ($(cd "${NESTED_SAIL_RISCV}" && git rev-parse --short HEAD))"

# --- summary --------------------------------------------------------------
log "Done"
printf '  TestRIG          %s @ %s\n' \
       "$(git branch --show-current || echo "(detached)")" \
       "$(git rev-parse --short HEAD)"
printf '  cheriot-sail     %s @ %s\n' \
       "$(cd "${CHERIOT_SAIL}" && git branch --show-current || echo "(detached)")" \
       "$(cd "${CHERIOT_SAIL}" && git rev-parse --short HEAD)"
printf '  sail-riscv       %s @ %s\n' \
       "$(cd "${NESTED_SAIL_RISCV}" && git branch --show-current || echo "(detached)")" \
       "$(cd "${NESTED_SAIL_RISCV}" && git rev-parse --short HEAD)"
