#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
#
# Sync the host repo to the policy branches AND run a Docker build.
#
# The Dockerfile's source-fetcher stage now does the same submodule
# init + branch checkout inside the image, so plain `docker compose
# build` already produces the right image. This wrapper exists so the
# *host* tree also gets aligned — useful when you want to:
#
#   - run ./run_two_phase.sh natively (no Docker), or
#   - inspect/edit submodule source files between builds and have the
#     working tree match what the next build will see.
#
# Pass any extra args to `docker compose build` — common ones:
#
#   ./scripts/docker_build.sh                 # default build
#   ./scripts/docker_build.sh --no-cache      # force a fresh rebuild
#   ./scripts/docker_build.sh testrig-fulltest --no-cache
#
# After this finishes:
#   docker compose up testrig-quicktest       # 10 traces
#   docker compose up testrig-fulltest        # 100 traces

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT}"

# Step 1 — submodule init + branch policy on the *host* tree.
# (The Dockerfile repeats this work inside its source-fetcher stage,
# so the build itself is robust even if you skip this step.)
"${SCRIPT_DIR}/setup_submodules.sh"

# Step 2 — docker build.
printf '\n\033[1;34m== docker compose build ==\033[0m\n'
docker compose build "$@"
