#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Phase 2 of two-phase execution: re-execute each ELF file produced by
# Phase 1 in the Sail RVFI simulator and capture both:
#
#   *_phase2.rvfi.bin   binary RVFI v1 trace from the ELF re-exec path
#                       (since the patched Sail binary now emits RVFI on
#                       this path; see riscv_sim.c:1228 onwards).
#   *_sail.log          full verbose Sail trace (-v all channels) for
#                       human inspection.

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
    p.add_argument('--rvfi-bin-dir',
                   help='where to write *_phase2.rvfi.bin binary RVFI '
                        'traces from the ELF re-exec path')
    p.add_argument('--sail-path', required=True,
                   help='path to cheri_riscv_rvfi_RV32 binary')
    p.add_argument('--inst-limit', type=int, default=500,
                   help='instruction execution limit (default: 500')
    p.add_argument('--skip-ibex', action='store_true',
                   help='kept for backwards compat; this runner is Sail-only')
    p.add_argument('-v', '--verbose', action='store_true')
    return p.parse_args()


def run_one(elf, out_log, sail, inst_limit, rvfi_bin=None):
    """Re-execute one ELF and capture trace channels + (optionally) RVFI.

    Bare ``-v`` (``--trace`` with no value) hits ``set_config_print``'s
    NULL-optarg branch and enables every print channel the binary
    supports: instructions, register writes, memory accesses, RVFI
    lines, platform events, and exceptions (see ``riscv_sim.c:109``).
    ``--rvfi-output`` now works on the ELF re-exec path as of the
    Phase-2 RVFI patch.
    """
    cmd = [sail, elf, '-v', '--trace-output', out_log,
           '-l', str(inst_limit)]
    if rvfi_bin is not None:
        cmd += ['--rvfi-output', rvfi_bin]
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
    # Success criteria: the verbose log was produced. The RVFI binary
    # is best-effort — if the Sail loop terminated before any insn
    # stepped (e.g. instr==0 at PC=0), only a halt packet lands in it.
    if op.isfile(out_log) and op.getsize(out_log) > 0:
        return True, None
    return False, (r.stderr or r.stdout or 'unknown')[:300]


def main():
    args = parse_args()
    if not op.isfile(args.sail_path):
        print(f'ERROR: sail binary not found: {args.sail_path}', file=sys.stderr)
        return 1

    os.makedirs(args.output_dir, exist_ok=True)
    if args.rvfi_bin_dir:
        os.makedirs(args.rvfi_bin_dir, exist_ok=True)
    elfs = sorted(glob.glob(op.join(args.elf_dir, '*.elf')))
    if not elfs:
        print(f'ERROR: no ELF files in {args.elf_dir}', file=sys.stderr)
        return 1

    print(f'Phase 2: re-executing {len(elfs)} ELF(s) → '
          f'{args.output_dir}/*_sail.log'
          + (f' + {args.rvfi_bin_dir}/*_phase2.rvfi.bin'
             if args.rvfi_bin_dir else ''))

    ok = fail = 0
    t0 = time.time()
    for i, elf in enumerate(elfs, 1):
        stem = op.splitext(op.basename(elf))[0]
        out = op.join(args.output_dir, f'{stem}_sail.log')
        rvfi_bin = (op.join(args.rvfi_bin_dir, f'{stem}_phase2.rvfi.bin')
                    if args.rvfi_bin_dir else None)
        success, err = run_one(elf, out, args.sail_path,
                               args.inst_limit, rvfi_bin=rvfi_bin)
        if success:
            ok += 1
            if args.verbose or i % 10 == 0 or i == len(elfs):
                print(f'  [{i}/{len(elfs)}] pass  {stem}')
        else:
            fail += 1
            print(f'  [{i}/{len(elfs)}] FAIL  {stem}: {err}')

    print(f'\nDone in {time.time() - t0:.1f}s — ok={ok} fail={fail}')
    # Random ELFs come from Phase 1 which already accepted partial fails;
    # don't propagate a single bad re-exec as a hard pipeline error.
    # Only treat zero-success as fatal.
    return 0 if ok > 0 else 1


if __name__ == '__main__':
    sys.exit(main())
