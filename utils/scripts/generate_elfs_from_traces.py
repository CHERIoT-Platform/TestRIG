#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Phase 1 of two-phase execution: for every ``trace_*.hex.txt`` file in the
# input directory, run the Sail RVFI simulator in instruction-file mode
# (``-f``) so it executes the random stream once and writes the final
# memory state out as an ELF via ``--elf-output``.

import argparse
import glob
import os
import os.path as op
import subprocess
import sys


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input-dir', required=True,
                   help='directory with trace_*.hex.txt files')
    p.add_argument('--output-dir', required=True,
                   help='where to write ELF dumps')
    p.add_argument('--sail-path', required=True,
                   help='path to cheri_riscv_rvfi_RV32 binary')
    p.add_argument('--inst-limit', type=int, default=10000)
    p.add_argument('--input-pattern', default='trace_*.hex.txt')
    p.add_argument('--rvfi-bin-dir',
                   help='also write binary RVFI v1 trace here '
                        '(one <name>.rvfi.bin per input)')
    p.add_argument('-v', '--verbose', action='store_true')
    return p.parse_args()


STRIP_EXTS = ('.hex.txt', '.txt', '.hex', '.S')


def stem(fname):
    for ext in STRIP_EXTS:
        if fname.endswith(ext):
            return fname[: -len(ext)]
    return op.splitext(fname)[0]


def main():
    args = parse_args()
    if not op.isfile(args.sail_path):
        print(f'ERROR: sail binary not found: {args.sail_path}', file=sys.stderr)
        return 1

    os.makedirs(args.output_dir, exist_ok=True)
    if args.rvfi_bin_dir:
        os.makedirs(args.rvfi_bin_dir, exist_ok=True)
    traces = sorted(glob.glob(op.join(args.input_dir, args.input_pattern)))
    if not traces:
        print(f'ERROR: no files matching {args.input_pattern} in '
              f'{args.input_dir}', file=sys.stderr)
        return 1

    print(f'Phase 1: {len(traces)} trace(s) → {args.output_dir}/*.elf'
          + (f' + {args.rvfi_bin_dir}/*.rvfi.bin' if args.rvfi_bin_dir else ''))

    ok = fail = 0
    for i, t in enumerate(traces, 1):
        name = stem(op.basename(t))
        elf = op.join(args.output_dir, f'{name}.elf')
        cmd = [args.sail_path, '-f', t, '--elf-output', elf,
               '-l', str(args.inst_limit)]
        if args.rvfi_bin_dir:
            rvfi_bin = op.join(args.rvfi_bin_dir, f'{name}.rvfi.bin')
            cmd += ['--rvfi-output', rvfi_bin]
        try:
            # errors='replace' is load-bearing: Sail occasionally emits
            # raw non-UTF-8 bytes on stderr (e.g. 0xEA from a register
            # dump after a fatal stop) which would otherwise raise
            # UnicodeDecodeError inside subprocess.communicate, killing
            # the whole batch even though the ELF was produced fine.
            r = subprocess.run(cmd, capture_output=True, text=True,
                               errors='replace', timeout=60)
        except subprocess.TimeoutExpired:
            fail += 1
            print(f'  [{i}/{len(traces)}] TIMEOUT {name}')
            continue
        if r.returncode == 0 and op.isfile(elf):
            ok += 1
            if args.verbose or i % 10 == 0 or i == len(traces):
                print(f'  [{i}/{len(traces)}] pass  {name}.elf')
        else:
            fail += 1
            err = (r.stderr or r.stdout or '')[:200]
            print(f'  [{i}/{len(traces)}] FAIL  {name}: {err}')

    print(f'\nDone — ok={ok} fail={fail}')
    return 0 if fail == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
