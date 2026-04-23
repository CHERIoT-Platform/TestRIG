#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
#
# Two-phase execution runner for CHERIoT TestRIG.
#
# Phase 1: generate random RV32 instructions and let Sail execute them
#          once, dumping final memory to an ELF.
# Phase 2: re-execute each ELF in Sail and emit a per-instruction text
#          RVFI trace.
#
# Usage: ./run_two_phase.sh [--count N] [--instructions N]
#                           [--architecture ARCH] [--work-dir DIR]
#                           [--clean] [--seed N]

set -euo pipefail

COUNT=10
INSTRUCTIONS=50
ARCHITECTURE="rv32ecZifencei_Xcheriot"
WORK_DIR="./two_phase_output"
SEED=""
CLEAN=0

usage() {
  sed -n '3,16p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--count)         COUNT="$2"; shift 2 ;;
    -n|--instructions)  INSTRUCTIONS="$2"; shift 2 ;;
    -a|--architecture)  ARCHITECTURE="$2"; shift 2 ;;
    -w|--work-dir)      WORK_DIR="$2"; shift 2 ;;
    -s|--seed)          SEED="$2"; shift 2 ;;
    --clean)            CLEAN=1; shift ;;
    -h|--help)          usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAIL="${SCRIPT_DIR}/riscv-implementations/cheriot-sail/c_emulator/cheri_riscv_rvfi_RV32"
SCRIPTS="${SCRIPT_DIR}/utils/scripts"

TRACE_DIR="${WORK_DIR}/traces"
ELF_DIR="${WORK_DIR}/elfs"
RESULTS_DIR="${WORK_DIR}/results"

log() { printf '\n\033[1;34m== %s ==\033[0m\n' "$*"; }
ok()  { printf '\033[0;32m  ok\033[0m %s\n' "$*"; }
die() { printf '\033[0;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

log "Two-phase execution: ${COUNT} traces × ${INSTRUCTIONS} instrs (${ARCHITECTURE})"
echo "  work dir:  ${WORK_DIR}"

# Clean only the *contents* — the dir itself might be a bind-mount (Docker).
if [[ ${CLEAN} -eq 1 && -d "${WORK_DIR}" ]]; then
  find "${WORK_DIR}" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true
  ok "cleaned ${WORK_DIR}"
fi
mkdir -p "${TRACE_DIR}" "${ELF_DIR}" "${RESULTS_DIR}"

# Prerequisites
[[ -x "${SAIL}" ]] || die "Sail RVFI binary not found/executable at ${SAIL}
  Build it: see BUILD_SAIL_MACOS.md (macOS) or riscv-implementations/cheriot-sail/RUNNING.md (Linux)"
command -v python3 >/dev/null || die "python3 not in PATH"
ok "Sail binary found"

# Phase 1a — generate random instruction streams.
log "Step 1/3  Generate ${COUNT} random instruction files"
SEED_ARG=()
[[ -n "${SEED}" ]] && SEED_ARG=(--seed "${SEED}")
python3 "${SCRIPTS}/batch_generate_instructions.py" \
  --count "${COUNT}" \
  --output-dir "${TRACE_DIR}" \
  --architecture "${ARCHITECTURE}" \
  --num-instructions "${INSTRUCTIONS}" \
  ${SEED_ARG[@]+"${SEED_ARG[@]}"}
N_TRACES=$(find "${TRACE_DIR}" -maxdepth 1 -name 'trace_*.hex.txt' | wc -l | tr -d ' ')
ok "generated ${N_TRACES} trace(s)"

# Phase 1b — run each hex file through Sail to produce a memory-dumped ELF.
log "Step 2/3  Phase 1 — execute traces in Sail, dump memory to ELF"
python3 "${SCRIPTS}/generate_elfs_from_traces.py" \
  --input-dir "${TRACE_DIR}" \
  --output-dir "${ELF_DIR}" \
  --sail-path "${SAIL}"
N_ELFS=$(find "${ELF_DIR}" -maxdepth 1 -name '*.elf' | wc -l | tr -d ' ')
ok "generated ${N_ELFS} ELF(s)"

# Phase 2 — re-execute the ELF and capture a text RVFI trace.
log "Step 3/3  Phase 2 — re-execute ELFs in Sail, capture RVFI text"
python3 "${SCRIPTS}/run_two_phase_execution.py" \
  --elf-dir "${ELF_DIR}" \
  --output-dir "${RESULTS_DIR}" \
  --sail-path "${SAIL}" \
  --skip-ibex
N_RVFI=$(find "${RESULTS_DIR}" -maxdepth 1 -name '*_sail.rvfi' | wc -l | tr -d ' ')
ok "generated ${N_RVFI} RVFI text trace(s)"

# Summary.
SUMMARY="${WORK_DIR}/SUMMARY.txt"
cat > "${SUMMARY}" <<EOF
Two-phase execution summary
===========================
date:          $(date)
architecture:  ${ARCHITECTURE}
count:         ${COUNT} traces × ${INSTRUCTIONS} instructions
traces:        ${N_TRACES}  (${TRACE_DIR}/trace_*.hex.txt)
ELFs:          ${N_ELFS}    (${ELF_DIR}/trace_*.elf)
RVFI text:     ${N_RVFI}    (${RESULTS_DIR}/trace_*_sail.rvfi)
EOF
log "Done"
cat "${SUMMARY}"
