#!/usr/bin/env python3
"""
Analyze text RVFI trace files.

Usage:
  ./analyze_rvfi.py results/trace_*.rvfi
  ./analyze_rvfi.py -v results/trace_*.rvfi
  ./analyze_rvfi.py "results/trace_*.rvfi"

Stats:
  0. Count total RVFI packets.
  1. Count unique instructions, where unique instruction means unique pc_rdata.
     Ratio = unique_pc_count / total_packets.
  2. Count unique RVFI packets, where uniqueness is based on:
       pc_rdata, insn, rd, rd_wdata,
       mem_addr, mem_rdata, mem_rmask,
       mem_wdata, mem_wmask
     Ratio = unique_packet_count / total_packets.

For the final SUM line, this script sums the per-file counts. It does not
build a global cross-file unique-PC or unique-packet set.
"""

import argparse
import glob
import os
import re
import sys


UNIQUE_PACKET_FIELDS = (
    "pc_rdata",
    "insn",
    "rd",
    "rd_wdata",
    "mem_addr",
    "mem_rdata",
    "mem_rmask",
    "mem_wdata",
    "mem_wmask",
)


RVFI_HEADER_RE = re.compile(r"^\s*#\s*---\s*RVFI packet\b")


def parse_int(s):
    """Parse the first integer from a string."""
    if s is None:
        return None

    m = re.search(r"0x[0-9a-fA-F_]+", s)
    if m is not None:
        return int(m.group(0).replace("_", ""), 16)

    m = re.search(r"0b[01_]+", s)
    if m is not None:
        return int(m.group(0).replace("_", ""), 2)

    m = re.search(r"\b[0-9]+\b", s)
    if m is not None:
        return int(m.group(0), 10)

    return None


def parse_named_int(s, name):
    """Parse name=<integer> from a string."""
    if s is None:
        return None

    pattern = r"\b{}\s*=\s*(0x[0-9a-fA-F_]+|0b[01_]+|[0-9]+)".format(
        re.escape(name)
    )
    m = re.search(pattern, s)
    if m is None:
        return None

    return parse_int(m.group(1))


def parse_rd_line(rest):
    """Parse an rd line like: rd : x13  wdata=0x..."""
    m = re.search(r"\bx([0-9]+)\b", rest)
    if m is not None:
        rd = int(m.group(1), 10)
    else:
        before_wdata = rest.split("wdata", 1)[0]
        rd = parse_int(before_wdata)

    rd_wdata = parse_named_int(rest, "wdata")
    return rd, rd_wdata


def new_file_stats():
    """Stats while parsing one file.

    The sets are per-file only. They are discarded after converting to counts.
    """
    return {
        "total_packets": 0,
        "unique_pcs": set(),
        "unique_packets": set(),
    }


def finish_packet(packet, stats):
    if packet is None:
        return

    stats["total_packets"] += 1

    pc = packet.get("pc_rdata")
    if pc is not None:
        stats["unique_pcs"].add(pc)

    key = tuple(packet.get(field) for field in UNIQUE_PACKET_FIELDS)
    stats["unique_packets"].add(key)


def parse_rvfi_file(path):
    stats = new_file_stats()
    packet = None

    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")

            if RVFI_HEADER_RE.match(line):
                finish_packet(packet, stats)
                packet = {}
                continue

            if packet is None:
                continue

            if ":" not in line:
                continue

            field, rest = line.split(":", 1)
            field = field.strip().lower()
            rest = rest.strip()

            if field in (
                "pc_rdata",
                "insn",
                "mem_addr",
                "mem_rdata",
                "mem_rmask",
                "mem_wdata",
                "mem_wmask",
            ):
                packet[field] = parse_int(rest)
                continue

            if field == "rd":
                rd, rd_wdata = parse_rd_line(rest)
                packet["rd"] = rd
                packet["rd_wdata"] = rd_wdata
                continue

            # Optional alternate trace formats.
            if field == "rd_addr":
                packet["rd"] = parse_int(rest)
                continue

            if field == "rd_wdata":
                packet["rd_wdata"] = parse_int(rest)
                continue

            # Optional combined memory format:
            #   mem : addr=0x... rmask=0x... rdata=0x... wmask=0x... wdata=0x...
            if field == "mem":
                addr = parse_named_int(rest, "addr")
                rmask = parse_named_int(rest, "rmask")
                rdata = parse_named_int(rest, "rdata")
                wmask = parse_named_int(rest, "wmask")
                wdata = parse_named_int(rest, "wdata")

                if addr is not None:
                    packet["mem_addr"] = addr
                if rmask is not None:
                    packet["mem_rmask"] = rmask
                if rdata is not None:
                    packet["mem_rdata"] = rdata
                if wmask is not None:
                    packet["mem_wmask"] = wmask
                if wdata is not None:
                    packet["mem_wdata"] = wdata
                continue

    finish_packet(packet, stats)
    return stats


def summarize_file_stats(stats):
    """Convert one file's sets to simple counts."""
    return {
        "total_packets": stats["total_packets"],
        "unique_pc_count": len(stats["unique_pcs"]),
        "unique_packet_count": len(stats["unique_packets"]),
    }


def new_total_summary():
    """Final summary is only sums of per-file summary counts."""
    return {
        "total_packets": 0,
        "unique_pc_count": 0,
        "unique_packet_count": 0,
    }


def add_summary(total, one):
    total["total_packets"] += one["total_packets"]
    total["unique_pc_count"] += one["unique_pc_count"]
    total["unique_packet_count"] += one["unique_packet_count"]


def ratio(num, den):
    if den == 0:
        return 0.0
    return float(num) / float(den)


def expand_inputs(patterns):
    """Expand wildcard patterns.

    Works whether the shell expanded the glob already or the user quoted it.
    """
    files = []

    for p in patterns:
        matches = sorted(glob.glob(p))
        if matches:
            files.extend(matches)
        else:
            files.append(p)

    out = []
    seen = set()
    for f in files:
        if f not in seen:
            seen.add(f)
            out.append(f)

    return out


def print_stats(label, summary):
    total_packets = summary["total_packets"]
    unique_instrs = summary["unique_pc_count"]
    unique_packets = summary["unique_packet_count"]

    print(label)
    print("  total RVFI packets        : {}".format(total_packets))
    print("  unique instructions / PCs : {}".format(unique_instrs))
    print("  unique PC ratio           : {:.6f}".format(ratio(unique_instrs, total_packets)))
    print("  unique RVFI packets       : {}".format(unique_packets))
    print("  unique RVFI packet ratio  : {:.6f}".format(ratio(unique_packets, total_packets)))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyze text RVFI trace files."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="print per-file stats as well as summed stats",
    )
    parser.add_argument(
        "files",
        nargs="+",
        help="RVFI text files or wildcard patterns, e.g. results/trace_*.rvfi",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    files = expand_inputs(args.files)

    existing_files = []
    for f in files:
        if os.path.isfile(f):
            existing_files.append(f)
        else:
            print("WARNING: skipping missing file: {}".format(f), file=sys.stderr)

    if not existing_files:
        print("ERROR: no input files found", file=sys.stderr)
        return 1

    total = new_total_summary()

    for path in existing_files:
        file_stats = parse_rvfi_file(path)
        summary = summarize_file_stats(file_stats)

        # Discard per-file sets here. Total only sums per-file counts.
        add_summary(total, summary)

        if args.verbose:
            print_stats(path, summary)

    if args.verbose:
        print("")

    print_stats("SUM over {} file(s)".format(len(existing_files)), total)
    return 0


if __name__ == "__main__":
    sys.exit(main())

