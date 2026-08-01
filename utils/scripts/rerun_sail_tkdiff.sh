#!/usr/bin/env bash
# Version: 3 - absolute host paths; install under utils/scripts
#
# Re-run one Phase-1 instruction trace through Sail inside the TestRIG
# Docker container, capture the verbose output, and compare it with the
# corresponding Phase-2 Sail log.
#
# Usage:
#   ./rerun_sail_tkdiff.sh trace_002
#
# Install this script as TestRIG/utils/scripts/rerun_sail_tkdiff.sh.
# It may be invoked from any working directory.

set -euo pipefail

usage() {
    echo "Usage: $0 <trace_name>" >&2
    echo "Example: $0 trace_002" >&2
    exit 2
}

[[ $# -eq 1 ]] || usage

test_name="${1%.hex.txt}"
test_name="${test_name##*/}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

if [[ ! -f "${repo_root}/docker-compose.yml" ]]; then
    echo "ERROR: TestRIG repository root not found at: ${repo_root}" >&2
    echo "       Place this script under TestRIG/utils/scripts/." >&2
    exit 1
fi

cd "${repo_root}"

trace_file="${repo_root}/two_phase_output/traces/${test_name}.hex.txt"
phase2_log="${repo_root}/two_phase_output/results/${test_name}_sail.log"
container_trace="two_phase_output/traces/${test_name}.hex.txt"

[[ -f "${trace_file}" ]] || {
    echo "ERROR: Trace file not found: ${trace_file}" >&2
    exit 1
}

[[ -f "${phase2_log}" ]] || {
    echo "ERROR: Phase-2 Sail log not found: ${phase2_log}" >&2
    exit 1
}

command -v docker >/dev/null 2>&1 || {
    echo "ERROR: docker is not available in PATH" >&2
    exit 1
}

command -v tkdiff >/dev/null 2>&1 || {
    echo "ERROR: tkdiff is not available in PATH" >&2
    exit 1
}

temp_dir="${repo_root}/temp"
mkdir -p "${temp_dir}"

temp_log="$(mktemp --tmpdir="${temp_dir}" \
    "${test_name}.rerun.XXXXXX.sail.log")"

cleanup() {
    rm -f "${temp_log}"
}
trap cleanup EXIT INT TERM

echo "Re-running ${test_name} in Docker..."
echo "Trace:       ${trace_file}"
echo "New log:     ${temp_log}"
echo "Phase-2 log: ${phase2_log}"

# docker-compose.yml sets the testrig working directory to /testrig and
# bind-mounts ./two_phase_output at /testrig/two_phase_output.
#
# -T disables the Compose pseudo-TTY so the captured log is plain text.
# tee writes the Sail output to the temporary host-side log and also displays it.
docker compose run --rm -T testrig \
    riscv-implementations/cheriot-sail/c_emulator/cheri_riscv_rvfi_RV32 \
    -v -f "${container_trace}" 2>&1 | tee "${temp_log}"

echo
echo "Opening tkdiff..."
tkdiff "${temp_log}" "${phase2_log}"
