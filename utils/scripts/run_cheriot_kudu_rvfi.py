#!/usr/bin/env python3
"""
Run TestRIG, prepare CHERIoT-Kudu simulation inputs, run Verilator simulations,
and compare Kudu RVFI traces against Sail/TestRIG phase-2 RVFI traces.

Expected to be run from the TestRIG repository root, or use --root.

Modes:
  quick  -> docker compose up testrig-quicktest
  full   -> docker compose up testrig-fulltest
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# ---- RVFI packet parsing and comparison ----

RVFI_PACKET_RE = re.compile(r"^\s*#\s*---\s*RVFI packet\s+([0-9]+)\s*---")
RVFI_FIELD_RE = re.compile(r"^\s*([A-Za-z0-9_]+)\s*:\s*(.*)$")
HEX_RE = re.compile(r"0x([0-9a-fA-F]+)")
DEC_RE = re.compile(r"\b([0-9]+)\b")
MASK64 = (1 << 64) - 1

COMPARE_FIELDS = [
    "packet_num",
    "trap",
    "intr",
    "pc_rdata",
    "insn",
    "rd",
    "rd_wdata",
    "mem_addr",
    "mem_rmask",
    "mem_rdata",
    "mem_wmask",
]

LOW64_FIELDS = set(["rd_wdata", "mem_rdata", "mem_wmask"])


@dataclass
class RvfiPacket:
    packet_num: int
    trap: Optional[int] = None
    intr: Optional[int] = None
    pc_rdata: Optional[int] = None
    insn: Optional[int] = None
    rd: Optional[int] = None
    rd_wdata: Optional[int] = None
    mem_addr: Optional[int] = None
    mem_rmask: Optional[int] = None
    mem_rdata: Optional[int] = None
    mem_wmask: Optional[int] = None


def parse_int(text):
    hex_match = HEX_RE.search(text)
    if hex_match is not None:
        return int(hex_match.group(1), 16)

    dec_match = DEC_RE.search(text)
    if dec_match is not None:
        return int(dec_match.group(1), 10)

    return None


def parse_named_int(rest, name):
    match = re.search(r"(?:^|\s){}=0x([0-9a-fA-F]+)".format(name), rest)
    if match is not None:
        return int(match.group(1), 16)

    match = re.search(r"(?:^|\s){}=([0-9]+)".format(name), rest)
    if match is not None:
        return int(match.group(1), 10)

    return None


def set_packet_field(packet, field, value):
    if value is None:
        return

    if field in LOW64_FIELDS:
        value &= MASK64

    setattr(packet, field, value)


def parse_rvfi_field(packet, field, rest):
    if field in ("trap", "intr", "pc_rdata", "insn", "mem_addr", "mem_rmask", "mem_rdata", "mem_wmask"):
        set_packet_field(packet, field, parse_int(rest))
        return

    if field == "rd":
        rd_match = re.search(r"\bx([0-9]+)\b", rest)
        if rd_match is not None:
            set_packet_field(packet, "rd", int(rd_match.group(1), 10))
        else:
            set_packet_field(packet, "rd", parse_int(rest.split("wdata", 1)[0]))

        set_packet_field(packet, "rd_wdata", parse_named_int(rest, "wdata"))
        return

    if field == "rd_wdata":
        set_packet_field(packet, "rd_wdata", parse_int(rest))
        return

    if field in ("rd_addr", "rd_id"):
        set_packet_field(packet, "rd", parse_int(rest))
        return

    if field == "mem":
        for attr in ("addr", "rmask", "rdata", "wmask"):
            value = parse_named_int(rest, attr)
            if attr == "addr":
                set_packet_field(packet, "mem_addr", value)
            else:
                set_packet_field(packet, "mem_{}".format(attr), value)


def iter_rvfi_packets(path):
    packet = None

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.split(";", 1)[0].rstrip()
            if not line:
                continue

            packet_match = RVFI_PACKET_RE.match(line)
            if packet_match is not None:
                if packet is not None:
                    yield packet
                packet = RvfiPacket(packet_num=int(packet_match.group(1), 10))
                continue

            if packet is None:
                continue

            field_match = RVFI_FIELD_RE.match(line)
            if field_match is None:
                continue

            field, rest = field_match.groups()
            parse_rvfi_field(packet, field, rest)

    if packet is not None:
        yield packet


def fmt_int(field, value):
    if value is None:
        return "<missing>"

    if field == "packet_num":
        return "{}".format(value)

    if field in ("trap", "intr", "rd"):
        return "{}".format(value)

    if field == "insn":
        return "0x{:08x}".format(value)

    if field in ("rd_wdata", "mem_rdata", "mem_wmask"):
        return "0x{:016x}".format(value & MASK64)

    return "0x{:x}".format(value)


def format_rvfi_packet(packet):
    return "\n".join(
        "    {:10s}: {}".format(field, fmt_int(field, getattr(packet, field)))
        for field in COMPARE_FIELDS
    )


def compare_rvfi_prefix(left, right):
    """
    Compare parsed RVFI packets until either file reaches EOF.

    Returns:
      (same_prefix, packet_index, diff_fields, left_packet, right_packet)

    packet_index counts parsed comparable packets, not original file lines.
    """
    lit = iter_rvfi_packets(left)
    rit = iter_rvfi_packets(right)

    packet_index = 0
    while True:
        try:
            lpacket = next(lit)
        except StopIteration:
            return True, None, None, None, None

        try:
            rpacket = next(rit)
        except StopIteration:
            return True, None, None, None, None

        packet_index += 1
        ignore_fields = set()
        if lpacket.trap == 1 and rpacket.trap == 1:
            ignore_fields.add("mem_addr")

        diff_fields = [
            field for field in COMPARE_FIELDS
            if field not in ignore_fields
            and getattr(lpacket, field) != getattr(rpacket, field)
        ]

        if diff_fields:
            return False, packet_index, diff_fields, lpacket, rpacket


# ---- filesystem helpers ----

def run_cmd(cmd, cwd=None):
    print("+ {}".format(" ".join(cmd)))
    subprocess.run(cmd, cwd=str(cwd) if cwd is not None else None, check=True)


def clean_dir(path):
    path.mkdir(parents=True, exist_ok=True)
    for entry in path.iterdir():
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(str(entry))
        else:
            entry.unlink()


def copy_all_files(src_dir, dst_dir):
    clean_dir(dst_dir)

    count = 0
    for entry in src_dir.iterdir():
        if entry.is_file():
            shutil.copy2(str(entry), str(dst_dir / entry.name))
            count += 1

    return count


def require_file(path, description):
    if not path.is_file():
        raise FileNotFoundError("{} not found: {}".format(description, path))


def require_dir(path, description):
    if not path.is_dir():
        raise FileNotFoundError("{} not found: {}".format(description, path))


# ---- workflow steps ----

def run_testrig(root, mode):
    service = {
        "quick": "testrig-quicktest",
        "full": "testrig-fulltest",
    }[mode]

    run_cmd(["docker", "compose", "up", service], cwd=root)


def prepare_sim_bin(root):
    src = root / "two_phase_output" / "elfs"
    sim_bin = root / "riscv-implementations" / "cheriot-kudu" / "sim" / "verilator" / "bin"

    require_dir(src, "TestRIG output directory")

    copied = copy_all_files(src, sim_bin)
    print("Copied {} file(s) from {} to {}".format(copied, src, sim_bin))

    return sim_bin

def prepare_ref_trace(root):
    src = root / "two_phase_output" / "results"
    ref_dir = root / "riscv-implementations" / "cheriot-kudu" / "sim" / "verilator" / "sail_results"
    require_dir(src, "TestRIG output directory")
    copied = copy_all_files(src, ref_dir)
    print("Copied {} file(s) from {} to {}".format(copied, src, ref_dir))
    return ref_dir

def convert_elfs_to_dii(root, sim_bin):
    elf2dii = root / "riscv-implementations" / "cheriot-kudu" / "sim" / "scripts" / "elf2dii.py"
    require_file(elf2dii, "elf2dii.py")

    elf_files = sorted(sim_bin.glob("*.elf"))
    if not elf_files:
        raise RuntimeError("No *.elf files found in {}".format(sim_bin))

    dii_files = []
    for elf in elf_files:
        dii = elf.with_suffix(".dii")
        run_cmd([str(elf2dii), str(elf), str(dii)], cwd=root)
        dii_files.append(dii)

    print("Generated {} .dii file(s)".format(len(dii_files)))
    return dii_files


def run_simulations(root, dii_files, timeout):
    verilator_dir = root / "riscv-implementations" / "cheriot-kudu" / "sim" / "verilator"
    sim_exe = verilator_dir / "obj_dir" / "Vtb_kudu_top"
    results_dir = verilator_dir / "results"

    require_file(sim_exe, "Verilator simulation executable")
    clean_dir(results_dir)

    for dii in sorted(dii_files):
        test_name = dii.stem
        print("Running simulation for {}".format(test_name))

        # Remove stale logs before each run so missing-output errors are real.
        for log_name in ["rvfi_kudu_core.log", "trace_kudu_core.log"]:
            stale = verilator_dir / log_name
            if stale.exists():
                stale.unlink()

        run_cmd([str(sim_exe), "+TEST={}".format(test_name), "+TIMEOUT={}".format(timeout)], cwd=verilator_dir)

        rvfi_log = verilator_dir / "rvfi_kudu_core.log"
        trace_log = verilator_dir / "trace_kudu_core.log"

        require_file(rvfi_log, "simulation RVFI log after test {}".format(test_name))
        require_file(trace_log, "simulation trace log after test {}".format(test_name))

        shutil.move(str(rvfi_log), str(results_dir / "{}.rvfi".format(test_name)))
        shutil.move(str(trace_log), str(results_dir / "{}.trace".format(test_name)))

    return results_dir


def find_sim_rvfi(results_dir, test_name):
    candidates = [
        results_dir / "{}.rvfi".format(test_name),
        results_dir / "rvfi_kudu_trace_{}.log".format(test_name),
    ]

    for path in candidates:
        if path.is_file():
            return path

    raise FileNotFoundError(
        "Could not find simulation RVFI for {}. Tried: {}".format(
            test_name, ", ".join(str(p) for p in candidates)
        )
    )


def find_reference_rvfi(sim_bin, test_name):
    candidates = [
        sim_bin / "{}_phase2.rvfi".format(test_name),
        sim_bin / "{}.rvfi".format(test_name),
    ]

    # If test_name already ends in _phase2, avoid requiring _phase2_phase2.rvfi.
    if test_name.endswith("_phase2"):
        base = test_name[:-len("_phase2")]
        candidates.insert(0, sim_bin / "{}_phase2.rvfi".format(base))
        candidates.insert(0, sim_bin / "{}.rvfi".format(test_name))

    for path in candidates:
        if path.is_file():
            return path

    raise FileNotFoundError(
        "Could not find reference RVFI for {}. Tried: {}".format(
            test_name, ", ".join(str(p) for p in candidates)
        )
    )


def check_results(sim_bin, results_dir):
    rvfi_files = sorted(results_dir.glob("*.rvfi"))
    if not rvfi_files:
        raise RuntimeError("No *.rvfi files found in {}".format(results_dir))

    for sim_rvfi in rvfi_files:
        test_name = sim_rvfi.stem
        ref_rvfi = find_reference_rvfi(sim_bin, test_name)

        print("Comparing:")
        print("  sim: {}".format(sim_rvfi))
        print("  ref: {}".format(ref_rvfi))

        ok, packet_index, diff_fields, left_packet, right_packet = compare_rvfi_prefix(sim_rvfi, ref_rvfi)
        if not ok:
            print("")
            print("FAIL: RVFI diff found for {}".format(test_name))
            print("  parsed packet index: {}".format(packet_index))
            print("  mismatched field(s): {}".format(", ".join(diff_fields)))
            print("  sim:")
            print(format_rvfi_packet(left_packet))
            print("  ref:")
            print(format_rvfi_packet(right_packet))
            raise SystemExit(1)

    print("")
    print("PASS: all RVFI comparisons matched. Happy! :)")


def main():
    parser = argparse.ArgumentParser(
        description="Run CHERIoT TestRIG, Kudu simulations, and RVFI comparison."
    )

    parser.add_argument(
        "mode",
        nargs="?",
        choices=["quick", "full"],
        help="Sail/TestRIG mode: quick runs testrig-quicktest, full runs testrig-fulltest",
    )

    parser.add_argument(
        "--root",
        default=".",
        help="TestRIG repository root. Default: current directory",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=1000,
        help="Verilator +TIMEOUT value. Default: 1000",
    )

    parser.add_argument(
        "--skip-sail",
        action="store_true",
        help="Skip Sail/TestRIG docker run and reuse existing two_phase_output/results",
    )

    parser.add_argument(
        "--skip-sim",
        action="store_true",
        help="Skip running simulations and only compare existing results",
    )

    args = parser.parse_args()

    if not args.skip_sail and not args.skip_sim and args.mode is None:
        parser.error("mode is required unless --skip-sail or --skip-sim is specified")

    root = Path(args.root).resolve()

    try:
        verilator_dir = root / "riscv-implementations" / "cheriot-kudu" / "sim" / "verilator"
        sim_bin = verilator_dir / "bin"
        results_dir = verilator_dir / "results"

        if args.skip_sim:
            ref_dir = verilator_dir / "sail_results"
            require_dir(results_dir, "existing simulation results directory")
            check_results(ref_dir, results_dir)
            return 0

        if not args.skip_sail:
            run_testrig(root, args.mode)

        sim_bin = prepare_sim_bin(root)
        ref_dir = prepare_ref_trace(root)
        dii_files = convert_elfs_to_dii(root, sim_bin)

        results_dir = run_simulations(root, dii_files, args.timeout)

        check_results(ref_dir, results_dir)
        return 0

    except subprocess.CalledProcessError as e:
        print("ERROR: command failed with return code {}".format(e.returncode), file=sys.stderr)
        return e.returncode if e.returncode != 0 else 1

    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 1

    except Exception as e:
        print("ERROR: {}".format(e), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
