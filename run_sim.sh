#!/usr/bin/env bash

set -u

usage() {
  echo "Usage: $0 [-rv32] [N]"
  echo "  -rv32  Build and run in RV32 mode"
  echo "  N      Number of wrapper runs (default: 1000)"
}

N=1000
N_SET=0
RV32=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    -rv32)
      RV32=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "ERROR: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [ "$N_SET" -eq 1 ]; then
        echo "ERROR: only one run count may be specified" >&2
        usage >&2
        exit 2
      fi
      N="$1"
      N_SET=1
      ;;
  esac
  shift
done

TOTAL_RUNS=0
STARTED_RUNS=0
PASS_RUNS=0
FAIL_RUNS=0

VERILOG_SIM_CASES=0
LAST_VERILOG_CASE=""
CURRENT_RUN=""

print_summary() {
  echo ""
  echo "===== run_sim.sh summary ====="
  echo "Total wrapper runs requested : ${TOTAL_RUNS}"
  echo "Wrapper runs started         : ${STARTED_RUNS}"
  echo "Wrapper runs passed          : ${PASS_RUNS}"
  echo "Wrapper runs failed          : ${FAIL_RUNS}"
  echo "Verilog simulation cases     : ${VERILOG_SIM_CASES}"

  if [ -n "${CURRENT_RUN}" ]; then
    echo "Last wrapper run             : ${CURRENT_RUN}"
  fi

  #if [ -n "${LAST_VERILOG_CASE}" ]; then
  #  echo "Last Verilog sim case        : ${LAST_VERILOG_CASE}"
  #fi
}

trap print_summary EXIT

if ! [[ "$N" =~ ^[0-9]+$ ]]; then
  echo "ERROR: N must be a positive integer" >&2
  exit 2
fi

if [ "$N" -eq 0 ]; then
  echo "ERROR: N must be > 0" >&2
  exit 2
fi

TOTAL_RUNS="${N}"

echo "===== building Verilator model ====="
(
  cd riscv-implementations/cheriot-kudu/sim/verilator || exit 1

  if [ "$RV32" -eq 1 ]; then
    ./vgen -dii -rv32 || exit $?
  else
    ./vgen -dii || exit $?
  fi

  ./vcomp
)
build_rc=$?

if [ "$build_rc" -ne 0 ]; then
  echo "ERROR: Verilator build failed with code $build_rc" >&2
  exit "$build_rc"
fi

RUNNER_ARGS=(full)
if [ "$RV32" -eq 1 ]; then
  RUNNER_ARGS+=(--sail-mode rv32)
fi

for ((i = 1; i <= N; i++)); do
  CURRENT_RUN="run ${i}"
  STARTED_RUNS=$((STARTED_RUNS + 1))

  echo "===== run $i / $N ====="

  tmp_log="$(mktemp)"
  python3 utils/scripts/run_cheriot_kudu_rvfi.py "${RUNNER_ARGS[@]}" 2>&1 | tee "$tmp_log"
  rc=${PIPESTATUS[0]}

  # Count Verilog simulation cases from the wrapper output.
  # Expected line format:
  #   Running verilog simulation for trace_001
  run_verilog_cases="$(grep -c 'Vtb_kudu_top\s*+TEST=' "$tmp_log" || true)"
  VERILOG_SIM_CASES=$((VERILOG_SIM_CASES + run_verilog_cases))

  last_case_line="$(grep 'Vtb_kudu_top\s*+TEST=' "$tmp_log" | tail -n 1 || true)"
  if [ -n "$last_case_line" ]; then
    LAST_VERILOG_CASE="${last_case_line#Running verilog simulation for }"
  fi

  last_line="$(tail -n 1 "$tmp_log")"
  rm -f "$tmp_log"

  if [ "$rc" -ne 0 ]; then
    FAIL_RUNS=$((FAIL_RUNS + 1))
    echo "STOP: run_cheriot_kudu_rvfi.py run $i exited with code $rc"
    exit "$rc"
  fi

  if [[ "$last_line" != PASS* && "$last_line" != "Conditional PASS"* ]]; then
    FAIL_RUNS=$((FAIL_RUNS + 1))
    echo "STOP: run $i last line did not start with PASS or Conditional PASS"
    echo "last line: $last_line"
    exit 1
  fi

  PASS_RUNS=$((PASS_RUNS + 1))
done

CURRENT_RUN=""

echo "PASS: completed $N successful wrapper run(s)"
