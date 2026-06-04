#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Phase 2 of two-phase execution: re-execute each ELF file produced by
# phase 1 in the Sail RVFI simulator and capture the *full* Sail trace
# (-v all: instr, reg, mem, rvfi, platform, exception channels) to
# ``<basename>_sail.log``.
#
# Note: the Sail binary's --rvfi-output path only fires in instruction-file
# (-f) mode (riscv_sim.c:1038-1039); re-executing an ELF does not emit a
# binary RVFI packet even though the RVFI model state is populated every
# step.  For labeled per-instruction RVFI, see Phase 1 (``trace_*.rvfi``).

import argparse
import glob
import os
import os.path as op
import subprocess
import sys
import time


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--elf-dir', required=True,
                   help='directory with phase-1 ELF files')
    p.add_argument('--output-dir', required=True,
                   help='where to write *_sail.log verbose Sail traces')
    p.add_argument('--sail-path', required=True,
                   help='path to cheri_riscv_rvfi_RV32 binary')
    p.add_argument('--inst-limit', type=int, default=10000,
                   help='instruction execution limit (default: 10000)')
    p.add_argument('--skip-ibex', action='store_true',
                   help='kept for backwards compat; this runner is Sail-only')
    p.add_argument('-v', '--verbose', action='store_true')
    return p.parse_args()


def run_one(elf, out_rvfi, sail, inst_limit):
    """Re-execute one ELF and capture Sail's full verbose trace.

    Bare ``-v`` (``--trace`` with no value) hits ``set_config_print``'s
    NULL-optarg branch and enables every print channel the binary
    supports: instructions, register writes, memory accesses, RVFI
    lines, platform events, and exceptions (see ``riscv_sim.c:109``).
    """
    cmd = [sail, elf, '-v', '--trace-output', out_rvfi,
           '-l', str(inst_limit)]
    try:
        # errors='replace': Phase 2 turns every Sail trace channel on
        # (-v / NULL optarg), and the verbose register/memory dumps can
        # include non-UTF-8 bytes that crash strict UTF-8 decoding inside
        # subprocess.communicate. Trace itself is written to a file via
        # --trace-output, so the captured stdout/stderr is only ever
        # consulted for error messages — lossy decode is fine here.
        r = subprocess.run(cmd, capture_output=True, text=True,
                           errors='replace', timeout=120)
    except subprocess.TimeoutExpired:
        return False, 'timeout'
    if op.isfile(out_rvfi) and op.getsize(out_rvfi) > 0:
        return True, None
    return False, (r.stderr or r.stdout or 'unknown')[:300]


def main():
    args = parse_args()
    if not op.isfile(args.sail_path):
        print(f'ERROR: sail binary not found: {args.sail_path}', file=sys.stderr)
        return 1

    os.makedirs(args.output_dir, exist_ok=True)
    elfs = sorted(glob.glob(op.join(args.elf_dir, '*.elf')))
    if not elfs:
        print(f'ERROR: no ELF files in {args.elf_dir}', file=sys.stderr)
        return 1

    print(f'Phase 2: re-executing {len(elfs)} ELF(s) → '
          f'{args.output_dir}/*_sail.log')

    ok = fail = 0
    t0 = time.time()
    for i, elf in enumerate(elfs, 1):
        stem = op.splitext(op.basename(elf))[0]
        out = op.join(args.output_dir, f'{stem}_sail.log')
        success, err = run_one(elf, out, args.sail_path, args.inst_limit)
        if success:
            ok += 1
            if args.verbose or i % 10 == 0 or i == len(elfs):
                print(f'  [{i}/{len(elfs)}] pass  {stem}')
        else:
            fail += 1
            print(f'  [{i}/{len(elfs)}] FAIL  {stem}: {err}')

    print(f'\nDone in {time.time() - t0:.1f}s — ok={ok} fail={fail}')
    return 0 if fail == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
