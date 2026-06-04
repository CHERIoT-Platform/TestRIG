#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
#
# Two-phase execution runner for CHERIoT TestRIG.
#
# Phase 1: generate random RV32 instructions; Sail executes them once,
#          dumps final memory to an ELF, AND emits a binary RVFI v1
#          trace (--rvfi-output).  The binary trace is decoded to
#          verbose labeled text: results/trace_NNN.rvfi.
# Phase 2: re-execute each ELF in Sail with all trace channels on
#          (-v) and capture the full Sail log: results/trace_NNN_sail.log.
#
# Usage: ./run_two_phase.sh [--count N] [--instructions N]
#                           [--architecture ARCH] [--work-dir DIR]
#                           [--clean] [--seed N]
#                           [--gen auto|qcvengine|python]
#                           [--template LABEL]

set -euo pipefail

COUNT=10
INSTRUCTIONS=50
ARCHITECTURE="rv32ecZifencei_Xcheriot"
WORK_DIR="./two_phase_output"
SEED=""
CLEAN=0
# Instruction-stream generator. "auto" (default) picks the QCVEngine
# Haskell binary when available and falls back to the Python script
# otherwise. Force one or the other with --gen qcvengine|python.
GEN="auto"
# QCVEngine template label (see QCVEngine --help / allTests in
# vengines/QuickCheckVEngine/src/QuickCheckVEngine/Main.hs). "random"
# is the closest equivalent to the old Python-generator mix.
TEMPLATE="random"

usage() {
  sed -n '3,18p' "$0" | sed 's/^# \{0,1\}//'
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
    --gen)              GEN="$2"; shift 2 ;;
    --template)         TEMPLATE="$2"; shift 2 ;;
    -h|--help)          usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAIL="${SCRIPT_DIR}/riscv-implementations/cheriot-sail/c_emulator/cheri_riscv_rvfi_RV32"
SCRIPTS="${SCRIPT_DIR}/utils/scripts"

TRACE_DIR="${WORK_DIR}/traces"
ELF_DIR="${WORK_DIR}/elfs"
RVFI_BIN_DIR="${WORK_DIR}/rvfi_bin"
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
mkdir -p "${TRACE_DIR}" "${ELF_DIR}" "${RVFI_BIN_DIR}" "${RESULTS_DIR}"

# Prerequisites
[[ -x "${SAIL}" ]] || die "Sail RVFI binary not found/executable at ${SAIL}
  Build it: see BUILD_SAIL_MACOS.md (macOS) or riscv-implementations/cheriot-sail/RUNNING.md (Linux)"
command -v python3 >/dev/null || die "python3 not in PATH"
ok "Sail binary found"

# Phase 1a — generate random instruction streams.
# Prefer the QCVEngine binary (authoritative CHERIoT encodings, lives at
# vengines/QuickCheckVEngine/src/RISCV/RV32_Xcheri.hs); fall back to the
# Python port when the binary isn't available (e.g. host runs without
# Docker and without a local cabal build).
log "Step 1/4  Generate ${COUNT} random instruction files (gen=${GEN})"

# Locate a QCVEngine executable. Priority: PATH, then a local cabal
# build tree, then the old binary copy the image used to install.
find_qcvengine() {
  if command -v qcvengine-gen >/dev/null 2>&1; then
    command -v qcvengine-gen
    return
  fi
  if command -v QCVEngine >/dev/null 2>&1; then
    command -v QCVEngine
    return
  fi
  local local_bin
  local_bin="${SCRIPT_DIR}/vengines/QuickCheckVEngine/dist-newstyle/build/$(uname -m)-linux/ghc-"*"/QCVEngine-"*"/x/QCVEngine/build/QCVEngine/QCVEngine"
  # shellcheck disable=SC2086
  set -- ${local_bin}
  if [[ -x "$1" ]]; then
    echo "$1"
    return
  fi
  return 1
}

QCV_BIN=""
case "${GEN}" in
  auto|qcvengine)
    QCV_BIN="$(find_qcvengine || true)"
    if [[ -z "${QCV_BIN}" && "${GEN}" == "qcvengine" ]]; then
      die "--gen qcvengine requested but QCVEngine binary not found on PATH
  Build it:  (cd vengines/QuickCheckVEngine && cabal v2-build exe:QCVEngine)
  Or use Docker, which builds it automatically."
    fi
    ;;
  python)
    : ;;
  *)
    die "Unknown --gen value: ${GEN} (use auto|qcvengine|python)" ;;
esac

if [[ -n "${QCV_BIN}" ]]; then
  ok "using QCVEngine generator: ${QCV_BIN}"
  SEED_ARG=()
  # QCVEngine does not accept a seed flag (randomness via QuickCheck's
  # generate); leaving SEED unused is the honest behaviour.
  [[ -n "${SEED}" ]] && echo "  note: --seed is ignored in QCVEngine mode"
  "${QCV_BIN}" \
      --output-dir "${TRACE_DIR}" \
      --output-count "${COUNT}" \
      --output-template "${TEMPLATE}" \
      --output-prefix "trace" \
      -L "${INSTRUCTIONS}" \
      -r "${ARCHITECTURE}"
else
  ok "using Python generator (fallback)"
  SEED_ARG=()
  [[ -n "${SEED}" ]] && SEED_ARG=(--seed "${SEED}")
  python3 "${SCRIPTS}/batch_generate_instructions.py" \
    --count "${COUNT}" \
    --output-dir "${TRACE_DIR}" \
    --architecture "${ARCHITECTURE}" \
    --num-instructions "${INSTRUCTIONS}" \
    ${SEED_ARG[@]+"${SEED_ARG[@]}"}
fi
N_TRACES=$(find "${TRACE_DIR}" -maxdepth 1 -name 'trace_*.hex.txt' | wc -l | tr -d ' ')
ok "generated ${N_TRACES} trace(s)"

# Phase 1b — run each hex file through Sail to produce a memory-dumped ELF
# *and* a binary RVFI v1 trace (--rvfi-output).
log "Step 2/4  Phase 1 — execute traces in Sail, dump memory to ELF + RVFI"
python3 "${SCRIPTS}/generate_elfs_from_traces.py" \
  --input-dir "${TRACE_DIR}" \
  --output-dir "${ELF_DIR}" \
  --rvfi-bin-dir "${RVFI_BIN_DIR}" \
  --sail-path "${SAIL}"
N_ELFS=$(find "${ELF_DIR}" -maxdepth 1 -name '*.elf' | wc -l | tr -d ' ')
N_RVFI_BIN=$(find "${RVFI_BIN_DIR}" -maxdepth 1 -name '*.rvfi.bin' | wc -l | tr -d ' ')
ok "generated ${N_ELFS} ELF(s), ${N_RVFI_BIN} binary RVFI trace(s)"

# Phase 1c — decode each binary RVFI v1 packet to verbose labeled text.
log "Step 3/4  Decode binary RVFI → verbose text (full field list + mnemonics)"
N_RVFI_TXT=0
for bin in "${RVFI_BIN_DIR}"/*.rvfi.bin; do
  [[ -e "${bin}" ]] || continue
  base=$(basename "${bin}" .rvfi.bin)
  out="${RESULTS_DIR}/${base}.rvfi"
  python3 "${SCRIPTS}/rvfi_to_text.py" \
    --input "${bin}" --output "${out}" --lenient >/dev/null
  N_RVFI_TXT=$((N_RVFI_TXT + 1))
done
ok "decoded ${N_RVFI_TXT} RVFI text trace(s) in ${RESULTS_DIR}/*.rvfi"

# Phase 2 — re-execute each ELF in Sail and capture the *full* Sail trace.
# Bare -v (NULL optarg in set_config_print) enables every channel:
# instr / reg / mem / rvfi / platform / exception.  The RVFI re-exec path
# in this binary does not route to --rvfi-output, so the log is the
# richest signal available for Phase-2 validation.
log "Step 4/4  Phase 2 — re-execute ELFs in Sail, capture full Sail trace"
python3 "${SCRIPTS}/run_two_phase_execution.py" \
  --elf-dir "${ELF_DIR}" \
  --output-dir "${RESULTS_DIR}" \
  --sail-path "${SAIL}" \
  --skip-ibex
N_RVFI=$(find "${RESULTS_DIR}" -maxdepth 1 -name '*_sail.log' | wc -l | tr -d ' ')
ok "generated ${N_RVFI} Sail re-exec log(s)"

# Summary.
SUMMARY="${WORK_DIR}/SUMMARY.txt"
cat > "${SUMMARY}" <<EOF
Two-phase execution summary
===========================
date:           $(date)
architecture:   ${ARCHITECTURE}
count:          ${COUNT} traces × ${INSTRUCTIONS} instructions
traces:         ${N_TRACES}      (${TRACE_DIR}/trace_*.hex.txt)
ELFs:           ${N_ELFS}        (${ELF_DIR}/trace_*.elf)
RVFI binary:    ${N_RVFI_BIN}    (${RVFI_BIN_DIR}/trace_*.rvfi.bin, v1)
RVFI text:      ${N_RVFI_TXT}    (${RESULTS_DIR}/trace_*.rvfi)       <-- primary
Phase-2 Sail:   ${N_RVFI}        (${RESULTS_DIR}/trace_*_sail.log)
EOF
log "Done"
cat "${SUMMARY}"
