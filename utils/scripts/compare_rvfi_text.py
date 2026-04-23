#!/usr/bin/env python3
#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 University of Cambridge
# All rights reserved.
#
# This script compares two RVFI text trace files field-by-field and reports
# any differences. Used in phase 2 of two-phase execution to verify that
# Sail (golden reference) and CHERIoT Ibex produce identical traces.

import argparse
import sys

## Parse arguments ##
parser = argparse.ArgumentParser(
    description='Compare two RVFI text trace files field-by-field')
parser.add_argument('file1', metavar='TRACE1', type=str,
                    help='First RVFI text trace file (e.g., Sail output)')
parser.add_argument('file2', metavar='TRACE2', type=str,
                    help='Second RVFI text trace file (e.g., Ibex output)')
parser.add_argument('-v', '--verbose', action='store_true',
                    help='Show all differences (not just first 10)')
parser.add_argument('-c', '--context', metavar='N', type=int, default=2,
                    help='Number of context lines to show around differences (default: 2)')
parser.add_argument('--ignore-fields', metavar='FIELDS', type=str,
                    help='Comma-separated list of field indices to ignore (0-based)')
args = parser.parse_args()

# RVFI V1 text format field names (for reference)
FIELD_NAMES = [
    "order",       # 0
    "pc_rdata",    # 1
    "pc_wdata",    # 2
    "insn",        # 3
    "trap",        # 4
    "halt",        # 5
    "intr",        # 6
    "rs1_addr",    # 7
    "rs1_rdata",   # 8
    "rs2_addr",    # 9
    "rs2_rdata",   # 10
    "rd_addr",     # 11
    "rd_wdata",    # 12
    "mem_addr",    # 13
    "mem_rmask",   # 14
    "mem_wmask",   # 15
    "mem_rdata",   # 16
    "mem_wdata",   # 17
]

def parse_rvfi_line(line):
    """Parse a single RVFI text line into fields."""
    fields = line.strip().split()
    return fields

def compare_traces(file1_path, file2_path, ignore_fields=None):
    """Compare two RVFI text trace files.

    Returns:
        (matches, mismatches, details)
        matches: number of matching lines
        mismatches: number of mismatched lines
        details: list of (line_num, field_idx, val1, val2) tuples
    """
    if ignore_fields is None:
        ignore_fields = set()

    matches = 0
    mismatches = 0
    details = []

    try:
        with open(file1_path, 'r') as f1, open(file2_path, 'r') as f2:
            lines1 = f1.readlines()
            lines2 = f2.readlines()

            # Check line count
            if len(lines1) != len(lines2):
                print(f"WARNING: Different number of lines: {len(lines1)} vs {len(lines2)}")

            # Compare line by line
            for line_num, (line1, line2) in enumerate(zip(lines1, lines2), start=1):
                # Skip empty lines
                if not line1.strip() or not line2.strip():
                    continue

                fields1 = parse_rvfi_line(line1)
                fields2 = parse_rvfi_line(line2)

                # Check field count
                if len(fields1) != len(fields2):
                    mismatches += 1
                    details.append((line_num, -1, len(fields1), len(fields2), "field_count"))
                    continue

                # Compare each field
                line_match = True
                for field_idx, (val1, val2) in enumerate(zip(fields1, fields2)):
                    if field_idx in ignore_fields:
                        continue

                    if val1 != val2:
                        line_match = False
                        field_name = FIELD_NAMES[field_idx] if field_idx < len(FIELD_NAMES) else f"field_{field_idx}"
                        details.append((line_num, field_idx, val1, val2, field_name))

                if line_match:
                    matches += 1
                else:
                    mismatches += 1

            # Handle extra lines in either file
            if len(lines1) > len(lines2):
                for line_num in range(len(lines2) + 1, len(lines1) + 1):
                    mismatches += 1
                    details.append((line_num, -2, "present", "missing", "extra_line_in_file1"))
            elif len(lines2) > len(lines1):
                for line_num in range(len(lines1) + 1, len(lines2) + 1):
                    mismatches += 1
                    details.append((line_num, -2, "missing", "present", "extra_line_in_file2"))

    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return None, None, None
    except Exception as e:
        print(f"ERROR: Failed to compare traces: {e}", file=sys.stderr)
        return None, None, None

    return matches, mismatches, details

def print_differences(details, max_show=10, verbose=False):
    """Print details of trace differences."""
    show_count = len(details) if verbose else min(len(details), max_show)

    for i, (line_num, field_idx, val1, val2, field_name) in enumerate(details[:show_count]):
        if field_idx == -1:
            print(f"  Line {line_num}: Field count mismatch: {val1} vs {val2}")
        elif field_idx == -2:
            print(f"  Line {line_num}: {field_name}")
        else:
            print(f"  Line {line_num}, field {field_idx} ({field_name}): {val1} vs {val2}")

    if not verbose and len(details) > max_show:
        print(f"  ... and {len(details) - max_show} more differences (use -v to see all)")

def main():
    print(f"Comparing RVFI traces:")
    print(f"  File 1: {args.file1}")
    print(f"  File 2: {args.file2}")

    # Parse ignore fields
    ignore_fields = set()
    if args.ignore_fields:
        try:
            ignore_fields = set(int(x) for x in args.ignore_fields.split(','))
            print(f"  Ignoring fields: {ignore_fields}")
        except ValueError:
            print(f"ERROR: Invalid --ignore-fields format: {args.ignore_fields}", file=sys.stderr)
            return 1

    # Compare traces
    matches, mismatches, details = compare_traces(args.file1, args.file2, ignore_fields)

    if matches is None:
        return 1

    # Print results
    total = matches + mismatches
    print(f"\nComparison Results:")
    print(f"  Matching lines:   {matches}/{total} ({100.0*matches/total if total > 0 else 0:.1f}%)")
    print(f"  Mismatched lines: {mismatches}/{total}")

    if mismatches > 0:
        print(f"\nDifferences found:")
        print_differences(details, max_show=10, verbose=args.verbose)
        return 1
    else:
        print("\nSUCCESS: Traces match!")
        return 0

if __name__ == '__main__':
    sys.exit(main())
