#!/usr/bin/env bash

set -u

N="${1:-1000}"

if ! [[ "$N" =~ ^[0-9]+$ ]]; then
  echo "ERROR: N must be a positive integer" >&2
  exit 2
fi

if [ "$N" -eq 0 ]; then
  echo "ERROR: N must be > 0" >&2
  exit 2
fi

for ((i = 1; i <= N; i++)); do
  echo "===== run $i / $N ====="

  tmp_log="$(mktemp)"
  python3 run_cheriot_kudu_rvfi.py full 2>&1 | tee "$tmp_log"
  rc=${PIPESTATUS[0]}

  last_line="$(tail -n 1 "$tmp_log")"
  rm -f "$tmp_log"

  if [ "$rc" -ne 0 ]; then
    echo "STOP: run_cheriot_kudu_rvfi.py run $i exited with code $rc"
    exit "$rc"
  fi

  if [[ "$last_line" != PASS* ]]; then
    echo "STOP: run $i last line did not start with PASS"
    echo "last line: $last_line"
    exit 1
  fi
done

echo "PASS: completed $N successful run(s)"
