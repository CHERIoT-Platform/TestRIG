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
# Usage: ./run_two_phase.sh [--case_cnt N] [--phase1_instr_count N]
#                           [--phase2_instr_count N]
#                           [--architecture ARCH] [--work-dir DIR]
#                           [--clean] [--seed N]
#                           [--gen auto|qcvengine|python]
#                           [--test TEST_NAME]

set -euo pipefail

COUNT=10
INSTRUCTIONS=1000
PHASE2_INSTRUCTIONS=""
ARCHITECTURE="rv32ecZifencei_Xcheriot"
WORK_DIR="./two_phase_output"
SEED=""
CLEAN=0
# Instruction-stream generator. "auto" (default) picks the QCVEngine
# Haskell binary when available and falls back to the Python script
# otherwise. Force one or the other with --gen qcvengine|python.
GEN="auto"
# QCVEngine template label (see allTests in
# vengines/QuickCheckVEngine/src/QuickCheckVEngine/Main.hs).
# "caprandom" = randomCHERITest in Templates/GenCHERI.hs — mixes
# legalLoad/Store, legalCapLoad/Store, the full rv32_xcheri set
# (inspection/arithmetic/misc/mem), cspecialrw, csrr, cspecialRWChain,
# makeShortCap, clearASR, boundPCC, cgettag, loadTags. Right default
# for a CHERIoT TestRIG because the whole point of this toolchain is
# testing CHERI capability behaviour. Override with --template random
# (pure RV32I) or --template caprvcrandom (caprandom + RVC) etc.
TEMPLATE="caprandom"
SAIL_MODEL="cheriot"
ARCHITECTURE=""
TEMPLATE=""

usage() {
  sed -n '3,18p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--count|--case_cnt)
      [[ $# -ge 2 ]] || { echo "ERROR: $1 requires a value" >&2; exit 2; }
      COUNT="$2"; shift 2 ;;
    -n|--instructions|--phase1_instr_count)
      [[ $# -ge 2 ]] || { echo "ERROR: $1 requires a value" >&2; exit 2; }
      INSTRUCTIONS="$2"; shift 2 ;;
    --phase2_instr_count)
      [[ $# -ge 2 ]] || { echo "ERROR: $1 requires a value" >&2; exit 2; }
      PHASE2_INSTRUCTIONS="$2"; shift 2 ;;
    -a|--architecture)  ARCHITECTURE="$2"; shift 2 ;;
    -w|--work-dir)      WORK_DIR="$2"; shift 2 ;;
    -s|--seed)          SEED="$2"; shift 2 ;;
    --sail-model) SAIL_MODEL="$2"; shift 2 ;;
    --clean)            CLEAN=1; shift ;;
    --gen)              GEN="$2"; shift 2 ;;
    --template|--test)
      [[ $# -ge 2 ]] || { echo "ERROR: $1 requires a value" >&2; exit 2; }
      TEMPLATE="$2"; shift 2 ;;
    -h|--help)          usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

: "${PHASE2_INSTRUCTIONS:=${INSTRUCTIONS}}"

for value_name in COUNT INSTRUCTIONS PHASE2_INSTRUCTIONS; do
  value="${!value_name}"
  if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "ERROR: ${value_name,,} must be a positive integer" >&2
    exit 2
  fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS="${SCRIPT_DIR}/utils/scripts"

# SAIL="${SCRIPT_DIR}/riscv-implementations/cheriot-sail/c_emulator/cheri_riscv_rvfi_RV32"
case "${SAIL_MODEL}" in
  cheriot)
    SAIL="${SCRIPT_DIR}/riscv-implementations/cheriot-sail/c_emulator/cheri_riscv_rvfi_RV32"
    : "${ARCHITECTURE:=rv32ecZifencei_Xcheriot}"
    : "${TEMPLATE:=caprandom}"
    ;;

  rv32)
    SAIL="${SCRIPT_DIR}/riscv-implementations/cheriot-sail/sail-riscv/c_emulator/riscv_rvfi_RV32"
    : "${ARCHITECTURE:=rv32imac}"
    : "${TEMPLATE:=random}"
    ;;

  *)
    die "Unknown --sail-model '${SAIL_MODEL}' (use cheriot or rv32)"
    ;;
esac

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

# Phase 1 — run each hex file through Sail to dump memory to an ELF.
# We deliberately do NOT ask Sail for Phase-1 RVFI; the deliverable is
# Phase-2 RVFI from the ELF re-exec path (matches Phase 2 = ELF → RVFI).
log "Step 2/4  Phase 1 — execute traces in Sail, dump memory to ELF"
python3 "${SCRIPTS}/generate_elfs_from_traces.py" \
  --input-dir "${TRACE_DIR}" \
  --output-dir "${ELF_DIR}" \
  --sail-path "${SAIL}"
N_ELFS=$(find "${ELF_DIR}" -maxdepth 1 -name '*.elf' | wc -l | tr -d ' ')
ok "generated ${N_ELFS} ELF(s)"

# Phase 2 — re-execute each ELF in Sail and capture BOTH:
#   1. The full verbose Sail trace (-v / NULL optarg → all channels:
#      instr / reg / mem / rvfi / platform / exception).
#   2. Binary RVFI v1 from the ELF re-exec path — enabled by the
#      Phase-2 RVFI patch in riscv_sim.c (rvfi_send_trace is now called
#      after each zstep in the ELF re-exec branch, and the trace fd is
#      opened for any mode that has --rvfi-output set, not just -f).
PHASE2_RVFI_BIN_DIR="${WORK_DIR}/rvfi_bin_phase2"
mkdir -p "${PHASE2_RVFI_BIN_DIR}"
log "Step 3/4  Phase 2 — re-execute ELFs in Sail, capture log + RVFI"
python3 "${SCRIPTS}/run_two_phase_execution.py" \
  --elf-dir "${ELF_DIR}" \
  --output-dir "${RESULTS_DIR}" \
  --rvfi-bin-dir "${PHASE2_RVFI_BIN_DIR}" \
  --sail-path "${SAIL}" \
  --inst-limit "${PHASE2_INSTRUCTIONS}" \
  --skip-ibex
N_RVFI=$(find "${RESULTS_DIR}" -maxdepth 1 -name '*_sail.log' | wc -l | tr -d ' ')
N_P2_BIN=$(find "${PHASE2_RVFI_BIN_DIR}" -maxdepth 1 -name '*_phase2.rvfi.bin' | wc -l | tr -d ' ')
ok "generated ${N_RVFI} Sail log(s), ${N_P2_BIN} Phase-2 RVFI binary trace(s)"

# Phase 2b — decode each binary RVFI v1 packet to verbose labeled text.
# Tolerate per-file decode failures (truncated binaries, etc.) so one
# malformed trace doesn't kill the whole step.
log "Step 4/4  Decode Phase-2 binary RVFI → verbose text"
N_P2_TXT=0
for bin in "${PHASE2_RVFI_BIN_DIR}"/*_phase2.rvfi.bin; do
  [[ -e "${bin}" ]] || continue
  base=$(basename "${bin}" .rvfi.bin)
  out="${RESULTS_DIR}/${base}.rvfi"
  if python3 "${SCRIPTS}/rvfi_to_text.py" \
       --input "${bin}" --output "${out}" --lenient >/dev/null 2>&1; then
    N_P2_TXT=$((N_P2_TXT + 1))
  else
    echo "  warn: failed to decode ${bin}" >&2
  fi
done
ok "decoded ${N_P2_TXT} Phase-2 RVFI text trace(s) in ${RESULTS_DIR}/*_phase2.rvfi"

# Summary.
SUMMARY="${WORK_DIR}/SUMMARY.txt"
cat > "${SUMMARY}" <<EOF
Two-phase execution summary
===========================
date:                 $(date)
architecture:         ${ARCHITECTURE}
count:                ${COUNT} traces × ${INSTRUCTIONS} instructions
phase-2 instr limit:  ${PHASE2_INSTRUCTIONS}

Phase 1 — generator → Sail (-f) → ELF
  hex traces:         ${N_TRACES}      (${TRACE_DIR}/trace_*.hex.txt)
  ELFs:               ${N_ELFS}        (${ELF_DIR}/trace_*.elf)

Phase 2 — ELF re-exec in Sail → log + binary RVFI
  Sail verbose log:   ${N_RVFI}        (${RESULTS_DIR}/trace_*_sail.log)
  RVFI binary:        ${N_P2_BIN}      (${PHASE2_RVFI_BIN_DIR}/trace_*_phase2.rvfi.bin)
  RVFI text:          ${N_P2_TXT}      (${RESULTS_DIR}/trace_*_phase2.rvfi)     <-- primary
EOF
log "Done"
cat "${SUMMARY}"
