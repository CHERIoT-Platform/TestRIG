#!/usr/bin/env python3
"""
Analyze text RVFI trace files.

Usage:
  ./analyze_rvfi.py results/trace_*.rvfi
  ./analyze_rvfi.py -v results/trace_*.rvfi
  ./analyze_rvfi.py --show-uncovered results/trace_*.rvfi
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
  3. Count useful loads and stores. A load/store is useful when its memory mask
     is nonzero and its mem_rdata/mem_wdata value is nonzero.
  4. In the final summary, count occurrences of each decoded RV32I, RV32M,
     RV32A, RV32B (Zba/Zbb/Zbs/Zbc), RV32C, or CHERIoT instruction.
  5. Report total occurrences and distinct mnemonic coverage for each of those
     three categories.
  6. With --show-uncovered, list instructions in those sets that had no
     occurrences.

For the final SUM line, this script sums the per-file counts. It does not
build a global cross-file unique-PC or unique-packet set.
"""

import argparse
from collections import Counter
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


ISA_ORDER = ("RV32I", "RV32M", "RV32A", "RV32B", "RV32C", "CHERIoT")
OCCURRENCE_ISA_ORDER = (
    "RV32I",
    "RV32M",
    "RV32A",
    "RV32B",
    "RV32-System",
    "RV32C",
    "CHERIoT",
    "UNKNOWN",
)

ISA_LABELS = {
    "RV32I": "RV32I",
    "RV32M": "RV32M",
    "RV32A": "RV32A",
    "RV32B": "RV32B",
    "RV32C": "RV32C (16-bit)",
    "RV32-System": "RV32 system",
    "CHERIoT": "CHERIoT",
    "UNKNOWN": "UNKNOWN",
}

# The zero-occurrence report uses the instruction sets implemented by the Sail
# model used by this flow. RV32B combines Zba, Zbb, Zbs, and Zbc.
RV32I_INSTRUCTIONS = frozenset((
    "lui", "auipc", "jal", "jalr",
    "beq", "bne", "blt", "bge", "bltu", "bgeu",
    "lb", "lh", "lw", "lbu", "lhu",
    "sb", "sh", "sw",
    "addi", "slti", "sltiu", "xori", "ori", "andi",
    "slli", "srli", "srai",
    "add", "sub", "sll", "slt", "sltu", "xor", "srl", "sra", "or", "and",
    "fence", "ecall", "ebreak",
))

RV32M_INSTRUCTIONS = frozenset((
    "mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu",
))

RV32A_INSTRUCTIONS = frozenset((
    "lr.w", "sc.w",
    "amoswap.w", "amoadd.w", "amoxor.w", "amoand.w", "amoor.w",
    "amomin.w", "amomax.w", "amominu.w", "amomaxu.w",
))

RV32B_INSTRUCTIONS = frozenset((
    # Zba
    "sh1add", "sh2add", "sh3add",
    # Zbb
    "andn", "orn", "xnor", "max", "maxu", "min", "minu", "rol", "ror",
    "rori", "sext.b", "sext.h", "zext.h", "rev8", "orc.b",
    "cpop", "clz", "ctz",
    # Zbs
    "bclr", "bext", "binv", "bset",
    "bclri", "bexti", "binvi", "bseti",
    # Zbc
    "clmul", "clmulh", "clmulr",
))

RV32C_INSTRUCTIONS = frozenset((
    "c.addi4spn", "c.lw", "c.sw",
    "c.nop", "c.addi", "c.jal", "c.li", "c.addi16sp", "c.lui",
    "c.srli", "c.srai", "c.andi", "c.sub", "c.xor", "c.or", "c.and",
    "c.j", "c.beqz", "c.bnez",
    "c.slli", "c.lwsp", "c.jr", "c.mv", "c.ebreak", "c.jalr",
    "c.add", "c.swsp",
))

CHERIOT_INSTRUCTIONS = frozenset((
    "auipcc", "auicgp", "cjal", "cjalr",
    "clc", "csc",
    "cgetperm", "cgettype", "cgetbase", "cgetlen", "cgettag",
    "cgetaddr", "cgethigh", "cgettop",
    "cmove", "ccleartag", "crrl", "cram",
    "cseal", "cunseal", "candperm", "csetaddr", "csethigh",
    "cincoffset", "cincoffsetimm",
    "csetbounds", "csetboundsexact", "csetboundsrounddown",
    "csetboundsimm", "csub", "ctestsubset", "cseqx",
    "cspecialr", "cspecialw", "cspecialrw",
    "c.clc", "c.clcsp", "c.csc", "c.cscsp",
    "c.cincaddr16csp", "c.cincaddr4cspn",
    "c.cjal", "c.cjalr", "c.cjr",
))

INSTRUCTION_UNIVERSES = {
    "RV32I": RV32I_INSTRUCTIONS,
    "RV32M": RV32M_INSTRUCTIONS,
    "RV32A": RV32A_INSTRUCTIONS,
    "RV32B": RV32B_INSTRUCTIONS,
    "RV32C": RV32C_INSTRUCTIONS,
    "CHERIoT": CHERIOT_INSTRUCTIONS,
}


def decode_compressed_instruction(insn):
    """Return (ISA group, mnemonic) for a 16-bit CHERIoT/RV32C instruction."""
    quadrant = insn & 0x3
    funct3 = (insn >> 13) & 0x7
    rd = (insn >> 7) & 0x1F
    rs2 = (insn >> 2) & 0x1F

    if quadrant == 0:
        if funct3 == 0 and ((insn >> 5) & 0xFF) == 0:
            return "UNKNOWN", "illegal-16"
        names = {
            0: ("CHERIoT", "c.cincaddr4cspn"),
            2: ("RV32C", "c.lw"),
            3: ("CHERIoT", "c.clc"),
            6: ("RV32C", "c.sw"),
            7: ("CHERIoT", "c.csc"),
        }
        return names.get(funct3, ("UNKNOWN", "unknown-16"))

    if quadrant == 1:
        if funct3 == 0:
            imm = ((insn >> 2) & 0x1F) | (((insn >> 12) & 1) << 5)
            if rd == 0 and imm == 0:
                return "RV32C", "c.nop"
            return "RV32C", "c.addi"
        if funct3 == 1:
            return "CHERIoT", "c.cjal"
        if funct3 == 2:
            return "RV32C", "c.li"
        if funct3 == 3:
            if rd == 2:
                return "CHERIoT", "c.cincaddr16csp"
            return "RV32C", "c.lui"
        if funct3 == 4:
            subop = (insn >> 10) & 0x3
            if subop == 0:
                return "RV32C", "c.srli"
            if subop == 1:
                return "RV32C", "c.srai"
            if subop == 2:
                return "RV32C", "c.andi"

            if ((insn >> 12) & 1) != 0:
                return "UNKNOWN", "unknown-16"

            return "RV32C", {
                0: "c.sub",
                1: "c.xor",
                2: "c.or",
                3: "c.and",
            }[(insn >> 5) & 0x3]
        if funct3 == 5:
            return "RV32C", "c.j"
        if funct3 == 6:
            return "RV32C", "c.beqz"
        if funct3 == 7:
            return "RV32C", "c.bnez"

    if quadrant == 2:
        if funct3 == 0:
            return "RV32C", "c.slli"
        if funct3 == 2:
            return "RV32C", "c.lwsp"
        if funct3 == 3:
            return "CHERIoT", "c.clcsp"
        if funct3 == 4:
            bit12 = (insn >> 12) & 1
            if bit12 == 0:
                if rs2 == 0 and rd != 0:
                    return "CHERIoT", "c.cjr"
                if rs2 != 0 and rd != 0:
                    return "RV32C", "c.mv"
            else:
                if rd == 0 and rs2 == 0:
                    return "RV32C", "c.ebreak"
                if rs2 == 0 and rd != 0:
                    return "CHERIoT", "c.cjalr"
                if rs2 != 0 and rd != 0:
                    return "RV32C", "c.add"
            return "UNKNOWN", "unknown-16"
        if funct3 == 6:
            return "RV32C", "c.swsp"
        if funct3 == 7:
            return "CHERIoT", "c.cscsp"

    return "UNKNOWN", "unknown-16"


def decode_cheriot_instruction(insn):
    """Decode CHERIoT instructions that use or replace 32-bit RV32 encodings."""
    opcode = insn & 0x7F
    funct3 = (insn >> 12) & 0x7
    funct7 = (insn >> 25) & 0x7F
    rd = (insn >> 7) & 0x1F
    rs1 = (insn >> 15) & 0x1F
    rs2 = (insn >> 20) & 0x1F

    if opcode == 0x17:
        return "CHERIoT", "auipcc"
    if opcode == 0x6F:
        return "CHERIoT", "cjal"
    if opcode == 0x67 and funct3 == 0:
        return "CHERIoT", "cjalr"
    if opcode == 0x7B:
        return "CHERIoT", "auicgp"
    if opcode == 0x03 and funct3 == 3:
        return "CHERIoT", "clc"
    if opcode == 0x23 and funct3 == 3:
        return "CHERIoT", "csc"

    if opcode != 0x5B:
        return None

    if funct3 == 1:
        return "CHERIoT", "cincoffsetimm"
    if funct3 == 2:
        return "CHERIoT", "csetboundsimm"
    if funct3 != 0:
        return "CHERIoT", "unknown-cheriot"

    if funct7 == 0x7F:
        name = {
            0x00: "cgetperm",
            0x01: "cgettype",
            0x02: "cgetbase",
            0x03: "cgetlen",
            0x04: "cgettag",
            0x08: "crrl",
            0x09: "cram",
            0x0A: "cmove",
            0x0B: "ccleartag",
            0x0F: "cgetaddr",
            0x17: "cgethigh",
            0x18: "cgettop",
        }.get(rs2)
        if name is not None:
            return "CHERIoT", name

    if funct7 == 0x01:
        if rs1 == 0:
            return "CHERIoT", "cspecialr"
        if rd == 0:
            return "CHERIoT", "cspecialw"
        return "CHERIoT", "cspecialrw"

    name = {
        0x08: "csetbounds",
        0x09: "csetboundsexact",
        0x0A: "csetboundsrounddown",
        0x0B: "cseal",
        0x0C: "cunseal",
        0x0D: "candperm",
        0x10: "csetaddr",
        0x11: "cincoffset",
        0x14: "csub",
        0x16: "csethigh",
        0x20: "ctestsubset",
        0x21: "cseqx",
    }.get(funct7)
    if name is not None:
        return "CHERIoT", name

    return "CHERIoT", "unknown-cheriot"


def decode_rv32b_instruction(insn):
    """Decode RV32 Zba, Zbb, Zbs, and Zbc instructions."""
    opcode = insn & 0x7F
    funct3 = (insn >> 12) & 0x7
    funct7 = (insn >> 25) & 0x7F
    rs2 = (insn >> 20) & 0x1F

    if opcode == 0x13:
        imm12 = (insn >> 20) & 0xFFF

        exact_immediate = {
            (1, 0x600): "clz",
            (1, 0x601): "ctz",
            (1, 0x602): "cpop",
            (1, 0x604): "sext.b",
            (1, 0x605): "sext.h",
            (5, 0x287): "orc.b",
            (5, 0x698): "rev8",
        }.get((funct3, imm12))
        if exact_immediate is not None:
            return "RV32B", exact_immediate

        name = {
            (1, 0x14): "bseti",
            (1, 0x24): "bclri",
            (1, 0x34): "binvi",
            (5, 0x24): "bexti",
            (5, 0x30): "rori",
        }.get((funct3, funct7))
        if name is not None:
            return "RV32B", name

    if opcode == 0x33:
        if funct7 == 0x10:
            name = {2: "sh1add", 4: "sh2add", 6: "sh3add"}.get(funct3)
            if name is not None:
                return "RV32B", name

        if funct7 == 0x20:
            name = {4: "xnor", 6: "orn", 7: "andn"}.get(funct3)
            if name is not None:
                return "RV32B", name

        if funct7 == 0x05:
            name = {
                1: "clmul",
                2: "clmulr",
                3: "clmulh",
                4: "min",
                5: "minu",
                6: "max",
                7: "maxu",
            }.get(funct3)
            if name is not None:
                return "RV32B", name

        if funct7 == 0x30:
            name = {1: "rol", 5: "ror"}.get(funct3)
            if name is not None:
                return "RV32B", name

        if funct7 == 0x04 and funct3 == 4 and rs2 == 0:
            return "RV32B", "zext.h"

        name = {
            (0x14, 1): "bset",
            (0x24, 1): "bclr",
            (0x24, 5): "bext",
            (0x34, 1): "binv",
        }.get((funct7, funct3))
        if name is not None:
            return "RV32B", name

    return None


def decode_instruction(insn):
    """Return (ISA group, mnemonic) for an RV32/CHERIoT instruction."""
    if insn is None:
        return None

    insn &= 0xFFFFFFFF
    if (insn & 0x3) != 0x3:
        return decode_compressed_instruction(insn & 0xFFFF)

    cheri = decode_cheriot_instruction(insn)
    if cheri is not None:
        return cheri

    bitmanip = decode_rv32b_instruction(insn)
    if bitmanip is not None:
        return bitmanip

    opcode = insn & 0x7F
    funct3 = (insn >> 12) & 0x7
    funct7 = (insn >> 25) & 0x7F

    if opcode == 0x37:
        return "RV32I", "lui"

    if opcode == 0x63:
        name = {
            0: "beq",
            1: "bne",
            4: "blt",
            5: "bge",
            6: "bltu",
            7: "bgeu",
        }.get(funct3)
        return ("RV32I", name) if name is not None else ("UNKNOWN", "unknown-32")

    if opcode == 0x03:
        name = {
            0: "lb",
            1: "lh",
            2: "lw",
            4: "lbu",
            5: "lhu",
        }.get(funct3)
        return ("RV32I", name) if name is not None else ("UNKNOWN", "unknown-32")

    if opcode == 0x23:
        name = {0: "sb", 1: "sh", 2: "sw"}.get(funct3)
        return ("RV32I", name) if name is not None else ("UNKNOWN", "unknown-32")

    if opcode == 0x13:
        if funct3 == 1 and funct7 == 0:
            return "RV32I", "slli"
        if funct3 == 5:
            if funct7 == 0:
                return "RV32I", "srli"
            if funct7 == 0x20:
                return "RV32I", "srai"
            return "UNKNOWN", "unknown-32"
        return "RV32I", {
            0: "addi",
            2: "slti",
            3: "sltiu",
            4: "xori",
            6: "ori",
            7: "andi",
        }.get(funct3, "unknown-32")

    if opcode == 0x33:
        if funct7 == 0x01:
            return "RV32M", {
                0: "mul",
                1: "mulh",
                2: "mulhsu",
                3: "mulhu",
                4: "div",
                5: "divu",
                6: "rem",
                7: "remu",
            }[funct3]
        if funct7 == 0:
            return "RV32I", {
                0: "add",
                1: "sll",
                2: "slt",
                3: "sltu",
                4: "xor",
                5: "srl",
                6: "or",
                7: "and",
            }[funct3]
        if funct7 == 0x20 and funct3 in (0, 5):
            return "RV32I", "sub" if funct3 == 0 else "sra"
        return "UNKNOWN", "unknown-32"

    if opcode == 0x0F:
        if funct3 == 0:
            return "RV32I", "fence"
        if funct3 == 1:
            return "RV32-System", "fence.i"
        return "UNKNOWN", "unknown-32"

    if opcode == 0x73:
        system = {
            0x00000073: "ecall",
            0x00100073: "ebreak",
            0x10500073: "wfi",
            0x30200073: "mret",
        }.get(insn)
        if system is not None:
            if system in ("ecall", "ebreak"):
                return "RV32I", system
            return "RV32-System", system

        name = {
            1: "csrrw",
            2: "csrrs",
            3: "csrrc",
            5: "csrrwi",
            6: "csrrsi",
            7: "csrrci",
        }.get(funct3)
        return (
            ("RV32-System", name)
            if name is not None
            else ("UNKNOWN", "unknown-32")
        )

    if opcode == 0x2F and funct3 == 2:
        name = {
            0x00: "amoadd.w",
            0x01: "amoswap.w",
            0x02: "lr.w",
            0x03: "sc.w",
            0x04: "amoxor.w",
            0x08: "amoor.w",
            0x0C: "amoand.w",
            0x10: "amomin.w",
            0x14: "amomax.w",
            0x18: "amominu.w",
            0x1C: "amomaxu.w",
        }.get((insn >> 27) & 0x1F)
        return ("RV32A", name) if name is not None else ("UNKNOWN", "unknown-32")

    return "UNKNOWN", "unknown-32"


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
        "useful_loads": 0,
        "useful_stores": 0,
        "instruction_counts": Counter(),
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

    if packet.get("mem_rmask", 0) != 0 and packet.get("mem_rdata", 0) != 0:
        stats["useful_loads"] += 1

    if packet.get("mem_wmask", 0) != 0 and packet.get("mem_wdata", 0) != 0:
        stats["useful_stores"] += 1

    if packet.get("halt", 0) == 0:
        decoded = decode_instruction(packet.get("insn"))
        if decoded is not None:
            stats["instruction_counts"][decoded] += 1


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
                "halt",
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
        "useful_loads": stats["useful_loads"],
        "useful_stores": stats["useful_stores"],
        "instruction_counts": stats["instruction_counts"].copy(),
    }


def new_total_summary():
    """Final summary is only sums of per-file summary counts."""
    return {
        "total_packets": 0,
        "unique_pc_count": 0,
        "unique_packet_count": 0,
        "useful_loads": 0,
        "useful_stores": 0,
        "instruction_counts": Counter(),
    }


def add_summary(total, one):
    total["total_packets"] += one["total_packets"]
    total["unique_pc_count"] += one["unique_pc_count"]
    total["unique_packet_count"] += one["unique_packet_count"]
    total["useful_loads"] += one["useful_loads"]
    total["useful_stores"] += one["useful_stores"]
    total["instruction_counts"].update(one["instruction_counts"])


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
    useful_loads = summary["useful_loads"]
    useful_stores = summary["useful_stores"]

    print(label)
    print("  total RVFI packets        : {}".format(total_packets))
    print("  unique instructions / PCs : {}".format(unique_instrs))
    print("  unique PC ratio           : {:.6f}".format(ratio(unique_instrs, total_packets)))
    print("  unique RVFI packets       : {}".format(unique_packets))
    print("  unique RVFI packet ratio  : {:.6f}".format(ratio(unique_packets, total_packets)))
    print("  useful loads              : {}".format(useful_loads))
    print("  useful stores             : {}".format(useful_stores))


def print_instruction_table(summary):
    counts = summary["instruction_counts"]
    total = sum(counts.values())

    print("")
    print("Instruction occurrences:")
    if total == 0:
        print("  no instruction fields found")
        return

    rows = sorted(
        counts.items(),
        key=lambda item: (
            {
                isa: index
                for index, isa in enumerate(OCCURRENCE_ISA_ORDER)
            }.get(item[0][0], len(OCCURRENCE_ISA_ORDER)),
            -item[1],
            item[0][1],
        ),
    )

    isa_width = max(
        len("ISA"),
        max(len(ISA_LABELS.get(key[0], key[0])) for key, unused in rows),
    )
    name_width = max(len("Instruction"), max(len(key[1]) for key, unused in rows))
    count_width = max(len("Count"), max(len(str(count)) for unused, count in rows))

    header = "  {isa:<{iw}}  {name:<{nw}}  {count:>{cw}}  {percent:>9}".format(
        isa="ISA",
        iw=isa_width,
        name="Instruction",
        nw=name_width,
        count="Count",
        cw=count_width,
        percent="Percent",
    )
    print(header)
    print("  {}  {}  {}  {}".format(
        "-" * isa_width,
        "-" * name_width,
        "-" * count_width,
        "-" * 9,
    ))

    for (isa, name), count in rows:
        print(
            "  {isa:<{iw}}  {name:<{nw}}  {count:>{cw}}  {percent:>8.2f}%".format(
                isa=ISA_LABELS.get(isa, isa),
                iw=isa_width,
                name=name,
                nw=name_width,
                count=count,
                cw=count_width,
                percent=100.0 * ratio(count, total),
            )
        )


def covered_instructions(summary, isa):
    """Return covered instruction names in one defined instruction universe."""
    universe = INSTRUCTION_UNIVERSES[isa]
    return {
        name
        for (group, name), count in summary["instruction_counts"].items()
        if group == isa and name in universe and count > 0
    }


def print_instruction_coverage(summary):
    """Print occurrence totals and coverage for the requested ISA groups."""
    rows = []
    rv32_groups = ("RV32I", "RV32M", "RV32A", "RV32B")
    rv32_occurrences = sum(
        count
        for (group, unused_name), count in summary["instruction_counts"].items()
        if group in rv32_groups
    )
    rv32_covered = sum(
        len(covered_instructions(summary, isa)) for isa in rv32_groups
    )
    rv32_total = sum(len(INSTRUCTION_UNIVERSES[isa]) for isa in rv32_groups)
    rows.append((
        "RV32 total (I/M/A/B)",
        rv32_occurrences,
        rv32_covered,
        rv32_total,
        ratio(rv32_covered, rv32_total),
    ))

    for isa in ISA_ORDER:
        occurrences = sum(
            count
            for (group, unused_name), count
            in summary["instruction_counts"].items()
            if group == isa
        )
        covered = len(covered_instructions(summary, isa))
        total = len(INSTRUCTION_UNIVERSES[isa])
        rows.append((
            ISA_LABELS[isa],
            occurrences,
            covered,
            total,
            ratio(covered, total),
        ))

    isa_width = max(len("ISA"), max(len(row[0]) for row in rows))
    occurrence_width = max(
        len("Occurrences"),
        max(len(str(row[1])) for row in rows),
    )
    covered_width = max(len("Covered"), max(len(str(row[2])) for row in rows))
    total_width = max(len("Available"), max(len(str(row[3])) for row in rows))

    print("")
    print("Instruction category totals and coverage:")
    print(
        "  {isa:<{iw}}  {occurrences:>{ow}}  {covered:>{cw}}  "
        "{total:>{tw}}  {coverage:>9}".format(
            isa="ISA",
            iw=isa_width,
            occurrences="Occurrences",
            ow=occurrence_width,
            covered="Covered",
            cw=covered_width,
            total="Available",
            tw=total_width,
            coverage="Coverage",
        )
    )
    print("  {}  {}  {}  {}  {}".format(
        "-" * isa_width,
        "-" * occurrence_width,
        "-" * covered_width,
        "-" * total_width,
        "-" * 9,
    ))

    for isa, occurrences, covered, total, coverage in rows:
        print(
            "  {isa:<{iw}}  {occurrences:>{ow}}  {covered:>{cw}}  "
            "{total:>{tw}}  {coverage:>8.2f}%".format(
                isa=isa,
                iw=isa_width,
                occurrences=occurrences,
                ow=occurrence_width,
                covered=covered,
                cw=covered_width,
                total=total,
                tw=total_width,
                coverage=100.0 * coverage,
            )
        )


def print_uncovered_instructions(summary):
    """List every defined instruction that had zero occurrences."""
    rows = []
    for isa in ISA_ORDER:
        uncovered = INSTRUCTION_UNIVERSES[isa] - covered_instructions(summary, isa)
        rows.extend((ISA_LABELS[isa], name) for name in sorted(uncovered))

    print("")
    print("Uncovered instructions (zero occurrences):")
    if not rows:
        print("  none")
        return

    isa_width = max(len("ISA"), max(len(row[0]) for row in rows))
    name_width = max(len("Instruction"), max(len(row[1]) for row in rows))

    print("  {isa:<{iw}}  {name:<{nw}}".format(
        isa="ISA",
        iw=isa_width,
        name="Instruction",
        nw=name_width,
    ))
    print("  {}  {}".format("-" * isa_width, "-" * name_width))

    for isa, name in rows:
        print("  {isa:<{iw}}  {name:<{nw}}".format(
            isa=isa,
            iw=isa_width,
            name=name,
            nw=name_width,
        ))


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
        "-u", "--show-uncovered",
        action="store_true",
        help=(
            "list RV32I/M/A/B, RV32C, and CHERIoT instructions with "
            "zero occurrences"
        ),
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
    print_instruction_table(total)
    print_instruction_coverage(total)
    if args.show_uncovered:
        print_uncovered_instructions(total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
