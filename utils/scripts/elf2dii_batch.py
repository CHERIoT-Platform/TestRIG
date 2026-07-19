#!/usr/bin/env python3
"""
Batch ELF-to-DII converter with Sail RVFI memory-write conflict checking.

Default behavior:
  1. Iterate over ./two_phase_output/elfs/trace*.elf
  2. For each trace_NNN.elf, find the corresponding Sail RVFI trace:
       ./two_phase_output/results/trace_NNN_phase2.rvfi
     with fallback:
       ./two_phase_output/trace_NNN_phase2.rvfi
  3. Check whether any RVFI memory write overlaps protected memory bytes:
       - ELF-loaded memory bytes
       - instruction bytes executed in the Sail RVFI trace, derived from pc_rdata/insn
     A memory write is any packet with mem_wmask != 0.
  4. If conflict is found, print an error and do not generate that .dii file.
  5. Otherwise write:
       ./riscv-implementations/cheriot-kudu/sim/verilator/bin/trace_NNN.dii

The DII output format matches elf2dii.py:
  mem[X,0xADDR] -> 0xWORD
"""

import argparse
import glob
import re
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile


RVFI_PACKET_RE = re.compile(r"^\s*#\s*---\s*RVFI packet\s+([0-9]+)\s*---")
RVFI_FIELD_RE = re.compile(r"^\s*([A-Za-z0-9_]+)\s*:\s*(.*)$")
HEX_RE = re.compile(r"0x([0-9a-fA-F_]+)")
BIN_RE = re.compile(r"0b([01_]+)")
DEC_RE = re.compile(r"\b([0-9]+)\b")


def parse_int(text):
    """Parse the first integer from a string."""
    if text is None:
        return None

    m = HEX_RE.search(text)
    if m is not None:
        return int(m.group(1).replace("_", ""), 16)

    m = BIN_RE.search(text)
    if m is not None:
        return int(m.group(1).replace("_", ""), 2)

    m = DEC_RE.search(text)
    if m is not None:
        return int(m.group(1), 10)

    return None


def iter_elf_load_ranges(elf_path, use_paddr=True, include_bss=True):
    """Yield byte ranges [start, end) covered by PT_LOAD segments."""
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)

        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue

            base_addr = seg["p_paddr"] if use_paddr else seg["p_vaddr"]
            file_size = seg["p_filesz"]
            mem_size = seg["p_memsz"]
            size = mem_size if include_bss else file_size

            if size <= 0:
                continue

            yield int(base_addr), int(base_addr + size)


def merge_ranges(ranges):
    """Merge [start, end) ranges."""
    sorted_ranges = sorted(ranges)
    merged = []

    for start, end in sorted_ranges:
        if start >= end:
            continue

        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        else:
            if end > merged[-1][1]:
                merged[-1][1] = end

    return [(start, end) for start, end in merged]


def ranges_overlap(start, end, ranges):
    """Return True if [start, end) overlaps any range in ranges."""
    if start >= end:
        return False

    for rstart, rend in ranges:
        if end <= rstart:
            return False
        if start < rend and end > rstart:
            return True

    return False


def wmask_to_write_ranges(mem_addr, mem_wmask):
    """Convert RVFI mem_addr + byte mask into written byte ranges.

    A mask bit N means byte at mem_addr + N is written.

    Examples:
      mem_wmask 0x01 -> [addr, addr+1)
      mem_wmask 0x03 -> [addr, addr+2)
      mem_wmask 0x0f -> [addr, addr+4)
      mem_wmask 0xff -> [addr, addr+8)

    Non-contiguous masks are returned as multiple coalesced ranges.
    """
    if mem_addr is None or mem_wmask is None or mem_wmask == 0:
        return []

    ranges = []
    active_start = None
    active_end = None

    for byte_index in range(8):
        if mem_wmask & (1 << byte_index):
            byte_addr = mem_addr + byte_index
            if active_start is None:
                active_start = byte_addr
                active_end = byte_addr + 1
            elif byte_addr == active_end:
                active_end += 1
            else:
                ranges.append((active_start, active_end))
                active_start = byte_addr
                active_end = byte_addr + 1

    if active_start is not None:
        ranges.append((active_start, active_end))

    # Debug only:
    # print("write ranges = {}".format(
    #     ["[0x{:x},0x{:x})".format(s, e) for s, e in ranges]
    # ))

    return ranges


def iter_rvfi_packets(rvfi_path):
    """Yield parsed RVFI packets with pc_rdata, insn, mem_addr, and mem_wmask."""
    packet = None

    def new_packet(packet_num):
        return {
            "packet_num": packet_num,
            "pc_rdata": None,
            "insn": None,
            "mem_addr": None,
            "mem_wmask": None,
        }

    with open(rvfi_path, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.split(";", 1)[0].strip()
            if not line:
                continue

            packet_match = RVFI_PACKET_RE.match(line)
            if packet_match is not None:
                if packet is not None:
                    yield packet

                packet = new_packet(int(packet_match.group(1), 10))
                continue

            field_match = RVFI_FIELD_RE.match(line)
            if field_match is None or packet is None:
                continue

            field, rest = field_match.groups()
            field = field.strip().lower()
            rest = rest.strip()

            if field == "pc_rdata":
                packet["pc_rdata"] = parse_int(rest)
            elif field == "insn":
                packet["insn"] = parse_int(rest)
            elif field == "mem_addr":
                packet["mem_addr"] = parse_int(rest)
            elif field == "mem_wmask":
                packet["mem_wmask"] = parse_int(rest)

    if packet is not None:
        yield packet


def rvfi_pc_ranges_from_packets(packets):
    """Return executed instruction byte ranges derived from RVFI pc_rdata/insn."""
    ranges = []

    for packet in packets:
        pc_rdata = packet["pc_rdata"]
        insn = packet["insn"]

        if pc_rdata is None or insn is None:
            continue

        insn_size = 4 if (insn & 0x3) == 0x3 else 2
        ranges.append((pc_rdata, pc_rdata + insn_size))

    return merge_ranges(ranges)


def find_rvfi_conflict(rvfi_path, elf_ranges):
    """Return conflict info or None.

    Protect both ELF-loaded bytes and instruction bytes executed according to
    RVFI pc_rdata/insn.
    """
    packets = list(iter_rvfi_packets(rvfi_path))
    pc_ranges = rvfi_pc_ranges_from_packets(packets)
    # protected_ranges = merge_ranges(list(elf_ranges) + list(pc_ranges))
    protected_ranges = pc_ranges

    # Debug only:
    # print("  ELF ranges:")
    # for start, end in elf_ranges:
    #     print("    [0x{:x}, 0x{:x})".format(start, end))
    # print("  RVFI PC ranges:")
    # for start, end in pc_ranges:
    #     print("    [0x{:x}, 0x{:x})".format(start, end))

    for packet in packets:
        mem_addr = packet["mem_addr"]
        mem_wmask = packet["mem_wmask"]

        if mem_wmask is None or mem_wmask == 0:
            continue

        for wstart, wend in wmask_to_write_ranges(mem_addr, mem_wmask):
            if ranges_overlap(wstart, wend, protected_ranges):
                conflict_kind = "unknown"
                if ranges_overlap(wstart, wend, elf_ranges):
                    conflict_kind = "elf"
                elif ranges_overlap(wstart, wend, pc_ranges):
                    conflict_kind = "rvfi_pc"

                return {
                    "packet_num": packet["packet_num"],
                    "mem_addr": mem_addr,
                    "mem_wmask": mem_wmask,
                    "write_start": wstart,
                    "write_end": wend,
                    "conflict_kind": conflict_kind,
                }

    return None


def elf_to_mem16(elf_path, out_path, x_name="X", use_paddr=True, include_bss=True):
    with open(elf_path, "rb") as f, open(out_path, "w") as out:
        elf = ELFFile(f)

        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue

            base_addr = seg["p_paddr"] if use_paddr else seg["p_vaddr"]
            file_size = seg["p_filesz"]
            mem_size = seg["p_memsz"]

            data = bytearray(seg.data())

            # Optional zero-fill for .bss-like part of PT_LOAD.
            if include_bss and mem_size > file_size:
                data.extend(b"\x00" * (mem_size - file_size))

            # Emit 16-bit words.
            for offset in range(0, len(data), 2):
                addr = base_addr + offset
                chunk = data[offset:offset + 2]

                # Pad final odd byte, if needed.
                if len(chunk) == 1:
                    chunk.append(0)

                # Little-endian 16-bit word:
                # byte at addr is low byte, byte at addr+1 is high byte.
                word = chunk[0] | (chunk[1] << 8)

                out.write("mem[{},0x{:08X}] -> 0x{:04X}\n".format(
                    x_name, addr, word
                ))


def find_rvfi_for_trace(root, rvfi_dir, trace_name):
    candidates = []

    if rvfi_dir is not None:
        candidates.append(rvfi_dir / "{}_phase2.rvfi".format(trace_name))
        candidates.append(rvfi_dir / "{}.rvfi".format(trace_name))

    candidates.extend([
        root / "two_phase_output" / "results" / "{}_phase2.rvfi".format(trace_name),
        root / "two_phase_output" / "results" / "{}.rvfi".format(trace_name),
        root / "two_phase_output" / "{}_phase2.rvfi".format(trace_name),
        root / "two_phase_output" / "{}.rvfi".format(trace_name),
    ])

    for path in candidates:
        if path.is_file():
            return path

    return None


def format_conflict(conflict):
    packet = conflict["packet_num"]
    packet_text = "<unknown>" if packet is None else str(packet)

    kind = conflict.get("conflict_kind", "unknown")

    return (
        "kind={}, packet={}, mem_addr=0x{:x}, mem_wmask=0x{:x}, "
        "written_range=[0x{:x}, 0x{:x})"
    ).format(
        kind,
        packet_text,
        conflict["mem_addr"] if conflict["mem_addr"] is not None else 0,
        conflict["mem_wmask"] if conflict["mem_wmask"] is not None else 0,
        conflict["write_start"],
        conflict["write_end"],
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Batch convert TestRIG trace*.elf files to .dii after RVFI write-conflict checks."
    )

    parser.add_argument(
        "--root",
        default=".",
        help="TestRIG repository root. Default: current directory.",
    )

    parser.add_argument(
        "--elf-glob",
        default="two_phase_output/elfs/trace*.elf",
        help="ELF glob relative to root. Default: two_phase_output/elfs/trace*.elf",
    )

    parser.add_argument(
        "--rvfi-dir",
        default=None,
        help=(
            "Directory containing Sail RVFI traces. Default: auto-search "
            "two_phase_output/results then two_phase_output."
        ),
    )

    parser.add_argument(
        "--out-dir",
        default="riscv-implementations/cheriot-kudu/sim/verilator/bin",
        help="Output directory relative to root. Default: Kudu verilator bin dir.",
    )

    parser.add_argument(
        "--x",
        default="X",
        help="Name/index to put in mem[X,addr]. Default: X.",
    )

    parser.add_argument(
        "--vaddr",
        action="store_true",
        help="Use p_vaddr instead of p_paddr.",
    )

    parser.add_argument(
        "--no-bss",
        action="store_true",
        help="Do not include zero-fill bytes for p_memsz > p_filesz.",
    )

    parser.add_argument(
        "--clean-out",
        action="store_true",
        help="Delete existing trace*.dii files in output directory before running.",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    root = Path(args.root).resolve()
    elf_pattern = str(root / args.elf_glob)
    out_dir = root / args.out_dir
    rvfi_dir = Path(args.rvfi_dir).resolve() if args.rvfi_dir is not None else None
    use_paddr = not args.vaddr
    include_bss = not args.no_bss

    elf_files = sorted(Path(p) for p in glob.glob(elf_pattern))
    if not elf_files:
        print("ERROR: no ELF files found: {}".format(elf_pattern), file=sys.stderr)
        return 1

    out_dir.mkdir(parents=True, exist_ok=True)

    if args.clean_out:
        for old in out_dir.glob("trace*.dii"):
            old.unlink()

    generated = 0
    skipped = 0
    failed = 0

    for elf_path in elf_files:
        trace_name = elf_path.stem
        rvfi_path = find_rvfi_for_trace(root, rvfi_dir, trace_name)
        out_path = out_dir / "{}.dii".format(trace_name)

        print("Processing {}".format(trace_name))
       # print("  elf : {}".format(elf_path))

        if rvfi_path is None:
            print("  ERROR: missing Sail RVFI trace for {}".format(trace_name), file=sys.stderr)
            skipped += 1
            failed += 1
            continue

       # print("  rvfi: {}".format(rvfi_path))
       # print("  out : {}".format(out_path))

        try:
            elf_ranges = merge_ranges(iter_elf_load_ranges(
                elf_path,
                use_paddr=use_paddr,
                include_bss=include_bss,
            ))

            conflict = find_rvfi_conflict(rvfi_path, elf_ranges)
            if conflict is not None:
                print("  WARNING: RVFI memory write overlaps ELF-loaded memory")
                print("  WARNING: {}".format(format_conflict(conflict)))
                print("  SKIP: not generating {}".format(out_path))
                skipped += 1
                continue

            elf_to_mem16(
                elf_path,
                out_path,
                x_name=args.x,
                use_paddr=use_paddr,
                include_bss=include_bss,
            )

            #print("  OK: generated {}".format(out_path))
            generated += 1

        except Exception as e:
            print("  ERROR: failed processing {}: {}".format(trace_name, e), file=sys.stderr)
            skipped += 1
            failed += 1
            continue

    print("")
    print("Summary:")
    print("  ELF files : {}".format(len(elf_files)))
    print("  generated : {}".format(generated))
    print("  skipped   : {}".format(skipped))

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
