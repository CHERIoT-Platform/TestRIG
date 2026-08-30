#!/usr/bin/env python3
"""
Run TestRIG, prepare CHERIoT-Kudu simulation inputs, run Verilator simulations,
and compare Kudu RVFI traces against Sail/TestRIG phase-2 RVFI traces.

Expected to be run from the TestRIG repository root, or use --root.

Use --case_cnt to override the number of generated tests, for example:
  run_cheriot_kudu_rvfi.py --case_cnt 500
"""

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# ---- RVFI packet parsing and comparison ----

RVFI_PACKET_RE = re.compile(r"^\s*#\s*---\s*RVFI packet\s+([0-9]+)\s*---")
RVFI_FIELD_RE = re.compile(r"^\s*([A-Za-z0-9_]+)\s*:\s*(.*)$")
HEX_RE = re.compile(r"0x([0-9a-fA-F]+)")
DEC_RE = re.compile(r"\b([0-9]+)\b")
BIN_RE = re.compile(r"0b([01_]+)")
MASK72 = (1 << 72) - 1

SUPPORTED_CSR_ADDRESSES = frozenset({
    0xF11,
    0xF12,
    0xF13,
    0xF14,
    0x300,
    0x301,
    0x304,
    0x305,
    0x340,
    0x341,
    0x342,
    0x343,
    0x344,
    0xB00,
}) | frozenset(range(0xBC5, 0xC00))

REMOTE_VCS_DIR = Path("/mnt/svceng/riscdev/super/sim/run_dii")
REMOTE_SSH_EXECUTABLE = Path("/mnt/c/Windows/System32/OpenSSH/ssh.exe")

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
    "mem_wmask",
    "mem_wdata"
]
#    "mem_rdata",   # remove mem_rdata for now as sail is looking directly at memory interface but 
                    # kudu tracer right now is looking at reg_wdata


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
    mem_wdata: Optional[int] = None


def parse_int(text):
    hex_match = HEX_RE.search(text)
    if hex_match is not None:
        return int(hex_match.group(1), 16)

    bin_match = BIN_RE.search(text)
    if bin_match is not None:
        return int(bin_match.group(1).replace("_", ""), 2)

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

    setattr(packet, field, value)


def parse_rvfi_field(packet, field, rest):
    if field in ("trap", "intr", "pc_rdata", "insn", "mem_addr", "mem_rmask", "mem_rdata", "mem_wmask", "mem_wdata"):
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


def count_rvfi_packets(path):
    """Count parsed RVFI packets in a text trace."""
    count = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.split(";", 1)[0].rstrip()
            if RVFI_PACKET_RE.match(line) is not None:
                count += 1
    return count


def fmt_int(field, value):
    if value is None:
        return "<missing>"

    if field == "packet_num":
        return "{}".format(value)

    if field in ("trap", "intr", "rd"):
        return "{}".format(value)

    if field == "insn":
        return "0x{:08x}".format(value)

    if field in ("rd_wdata", "mem_rdata", "mem_wdata"):
        return "0x{:018x}".format(value & MASK72)

    return "0x{:x}".format(value)


def format_rvfi_packet(packet):
    return "\n".join(
        "    {:10s}: {}".format(field, fmt_int(field, getattr(packet, field)))
        for field in COMPARE_FIELDS
    )

def normalize_cap_data(value):
    """Normalize capability data before comparison.

    cexp is bits [53:49]. Decode exp as:
      exp = 0                    when cexp == 0
      exp = cexp ^ 0x1f          otherwise

    When exp > 0x18, bits [48:32] are ignored by clearing them.
    """
    if value is None:
        return None

    cexp = (value >> 49) & 0x1f
    exp = cexp if cexp == 0 else (cexp ^ 0x1f)
    tag = (value >> 64) & 0x1

    if tag == 0 and exp > 0x18:
        value &= ~(((1 << 17) - 1) << 32)

    return value


def normalize_packet_cap_data(packet):
    """Apply capability-data normalization to compared data fields."""
    packet.rd_wdata = normalize_cap_data(packet.rd_wdata)
    packet.mem_wdata = normalize_cap_data(packet.mem_wdata)


def mask_packet_mem_data(packet):
    """Post-process memory data fields before comparison.

    After this runs:
      mem_rdata only contains bytes enabled by mem_rmask.
      mem_wdata only contains bytes enabled by mem_wmask.

    Special case:
      mask 0xff -> keep full parsed value unchanged
    """
    if packet.mem_rdata is not None and packet.mem_rmask is not None:
        if packet.mem_rmask != 0xff:
            data_mask = 0
            for byte_index in range(8):
                if packet.mem_rmask & (1 << byte_index):
                    data_mask |= 0xff << (8 * byte_index)
            packet.mem_rdata &= data_mask

    if packet.mem_wdata is not None and packet.mem_wmask is not None:
        if packet.mem_wmask != 0xff:
            data_mask = 0
            for byte_index in range(8):
                if packet.mem_wmask & (1 << byte_index):
                    data_mask |= 0xff << (8 * byte_index)
            packet.mem_wdata &= data_mask


def decode_csr_address(insn):
    """Return the 12-bit CSR address for a CSR instruction, or None."""
    if insn is None:
        return None

    insn &= 0xffffffff
    opcode = insn & 0x7f
    funct3 = (insn >> 12) & 0x7
    if opcode != 0x73 or funct3 not in (0b001, 0b010, 0b011, 0b101, 0b110, 0b111):
        return None

    return (insn >> 20) & 0xfff


def is_memory_load_store(insn):
    """Recognize RV32I and RV32C load/store instructions."""
    if insn is None:
        return False

    insn &= 0xffffffff

    # A 32-bit instruction has bits [1:0] == 2'b11.
    if (insn & 0x3) == 0x3:
        return (insn & 0x7f) in (0x03, 0x23)

    # RV32C C.LW/C.SW and C.LWSP/C.SWSP.
    quadrant = insn & 0x3
    funct3 = (insn >> 13) & 0x7
    return quadrant in (0b00, 0b10) and funct3 in (0b010, 0b110)


def is_amo(insn):
    """Return True for a 32-bit RISC-V atomic-memory instruction."""
    return insn is not None and (insn & 0x7f) == 0x2f


def relaxed_compare_reason(
    left_packet,
    right_packet,
    diff_fields,
    sail_mode,
    supported_csrs,
):
    """Return the matching relaxed-comparison rule, or None."""
    if (
        sail_mode == "rv32"
        and "insn" in diff_fields
        and left_packet.pc_rdata == 0
        and right_packet.pc_rdata == 0
    ):
        return "instruction mismatch at pc_rdata 0x0"

    same_instruction = (
        left_packet.insn is not None
        and right_packet.insn is not None
        and (left_packet.insn & 0xffffffff) == (right_packet.insn & 0xffffffff)
    )

    if same_instruction:
        csr_addr = decode_csr_address(left_packet.insn)
        if csr_addr is not None and csr_addr not in supported_csrs:
            return "CSR address 0x{:03x} is outside the supported CSR ranges".format(
                csr_addr
            )

    if sail_mode == "cheriot" and same_instruction and is_amo(left_packet.insn):
        return "CHERIoT AMO instruction (opcode 0x2f)"

    if (
        sail_mode == "rv32"
        and same_instruction
        and is_memory_load_store(left_packet.insn)
        and left_packet.trap == 0
        and right_packet.trap == 0
    ):
        for packet in (left_packet, right_packet):
            memory_active = (
                (packet.mem_rmask is not None and packet.mem_rmask != 0)
                or (packet.mem_wmask is not None and packet.mem_wmask != 0)
            )
            if packet.mem_addr == 0 and memory_active:
                return (
                    "RV32 untrapped load/store accessed address 0x0 with a "
                    "nonzero memory mask"
                )

    return None

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
            ignore_fields.add("mem_rmask")
            ignore_fields.add("mem_wmask")
            ignore_fields.add("mem_rdata")
            ignore_fields.add("mem_wdata")
            ignore_fields.add("insn")

        mask_packet_mem_data(lpacket)
        mask_packet_mem_data(rpacket)

        normalize_packet_cap_data(lpacket)
        normalize_packet_cap_data(rpacket)

        diff_fields = [
            field for field in COMPARE_FIELDS
            if field not in ignore_fields
            and getattr(lpacket, field) != getattr(rpacket, field)
        ]

        if diff_fields:
            return False, packet_index, diff_fields, lpacket, rpacket


# ---- filesystem helpers ----

#def run_cmd(cmd, cwd=None):
#    print("+ {}".format(" ".join(cmd)))
#    subprocess.run(cmd, cwd=str(cwd) if cwd is not None else None, check=True)
def run_cmd(cmd, cwd=None, quiet=False):
    printable_cmd = list(str(x) for x in cmd)
    if printable_cmd:
        printable_cmd[0] = os.path.basename(printable_cmd[0])

    print("+ {}".format(shlex.join(printable_cmd)))
    #print("+ {}".format(" ".join(cmd)))

    if quiet:
        with open(os.devnull, "w") as devnull:
            subprocess.run(
                cmd,
                cwd=cwd,
                check=True,
                stdout=devnull,
                stderr=devnull,
            )
    else:
        subprocess.run(cmd, cwd=cwd, check=True)


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

def run_testrig(
    root,
    sail_mode,
    case_cnt=100,
    phase1_instr_count=1000,
    phase2_instr_count=None,
    test_name=None,
    phase1_no_sail=False,
    stop_after=None,
):
    if case_cnt is None:
        case_cnt = 100
    if phase2_instr_count is None:
        phase2_instr_count = phase1_instr_count

    sail_model = "rv32" if sail_mode == "rv32" else "cheriot"

    command_args = [
        "./run_two_phase.sh",
        "--case_cnt", str(case_cnt),
        "--phase1_instr_count", str(phase1_instr_count),
        "--phase2_instr_count", str(phase2_instr_count),
        "--sail-model", sail_model,
        "--clean",
    ]
    if test_name is not None:
        command_args.extend(["--test", test_name])
    if phase1_no_sail:
        command_args.append("--phase1_no_sail")
    if stop_after == "vengine":
        command_args.append("--vengine-only")
    elif stop_after == "phase1":
        command_args.append("--phase1-only")
    elif stop_after is not None:
        raise ValueError("invalid stop_after value: {}".format(stop_after))
    command = " ".join(shlex.quote(arg) for arg in command_args)
    command += (
        "; run_status=$?; "
        "find ./two_phase_output -type d -exec chmod a+rwx {} +; "
        "chmod_status=$?; "
        "if [ $run_status -ne 0 ]; then exit $run_status; fi; "
        "exit $chmod_status"
    )

    run_cmd(
        [
            "docker",
            "compose",
            "run",
            "--rm",
            "testrig",
            "bash",
            "-lc",
            command,
        ],
        cwd=root,
    )


def run_phase2_sail(root, sail_mode, phase2_instr_count):
    elf_dir = root / "two_phase_output" / "elfs"
    rvfi_to_text = root / "utils" / "scripts" / "rvfi_to_text.py"

    require_dir(elf_dir, "existing Phase-1 ELF directory")
    require_file(rvfi_to_text, "rvfi_to_text.py")

    if sail_mode == "rv32":
        sail_path = (
            "./riscv-implementations/cheriot-sail/sail-riscv/"
            "c_emulator/riscv_rvfi_RV32"
        )
    else:
        sail_path = (
            "./riscv-implementations/cheriot-sail/"
            "c_emulator/cheri_riscv_rvfi_RV32"
        )

    command_args = [
        "python3",
        "./utils/scripts/run_phase2_sail.py",
        "--elf-dir", "./two_phase_output/elfs",
        "--output-dir", "./two_phase_output/results",
        "--rvfi-bin-dir", "./two_phase_output/rvfi_bin_phase2",
        "--sail-path", sail_path,
        "--inst-limit", str(phase2_instr_count),
        "--skip-ibex",
    ]
    command = " ".join(shlex.quote(arg) for arg in command_args)
    command += (
        "; run_status=$?; "
        "decoded=0; "
        "if [ $run_status -eq 0 ]; then "
        "for rvfi_bin in "
        "./two_phase_output/rvfi_bin_phase2/*_phase2.rvfi.bin; do "
        "[ -e \"$rvfi_bin\" ] || continue; "
        "base=$(basename \"$rvfi_bin\" .rvfi.bin); "
        "if python3 ./utils/scripts/rvfi_to_text.py "
        "--input \"$rvfi_bin\" "
        "--output \"./two_phase_output/results/${base}.rvfi\" "
        "--lenient; then "
        "decoded=$((decoded + 1)); "
        "else echo \"WARNING: failed to decode $rvfi_bin\" >&2; fi; "
        "done; "
        "echo \"Decoded ${decoded} Phase-2 RVFI trace(s).\"; "
        "fi; "
        "find ./two_phase_output -type d -exec chmod a+rwx {} +; "
        "chmod_status=$?; "
        "if [ $run_status -ne 0 ]; then exit $run_status; fi; "
        "exit $chmod_status"
    )

    print("\nRunning Phase-2 Sail simulation with existing ELFs ...", flush=True)
    run_cmd(
        [
            "docker",
            "compose",
            "run",
            "--rm",
            "testrig",
            "bash",
            "-lc",
            command,
        ],
        cwd=root,
    )

def prepare_sim_bin(root):
    src = root / "two_phase_output" / "elfs"
    sim_bin = root / "riscv-implementations" / "cheriot-kudu" / "sim" / "verilator" / "bin"

    require_dir(src, "TestRIG output directory")

    print("\nCopying ELFs from sail runs to verilog sim area ...", flush=True)
    copied = copy_all_files(src, sim_bin)
    print("Copied {} file(s) from {} to {}".format(copied, src, sim_bin))

    return sim_bin

def prepare_ref_trace(root):
    src = root / "two_phase_output" / "results"
    ref_dir = root / "riscv-implementations" / "cheriot-kudu" / "sim" / "verilator" / "sail_results"
    require_dir(src, "TestRIG output directory")
    print("\nCopying traces from phase 2 sail runs to verilog sim area ...", flush=True)
    copied = copy_all_files(src, ref_dir)
    print("Copied {} file(s) from {} to {}".format(copied, src, ref_dir))
    return ref_dir

def convert_elfs_to_dii(root):
    elf2dii = root / "utils" / "scripts" / "elf2dii_batch.py"
    elf_list = root / "two_phase_output" / "elfs" / "elfs_no_conflict.list"
    require_file(elf2dii, "elf2dii_batch.py")

    print("Checking ELF files for instruction-memory conflicts ...", flush=True)
    run_cmd([str(elf2dii)], cwd=root, quiet=False)

    require_file(elf_list, "conflict-free ELF list")
    dii_files = []
    with elf_list.open("r", encoding="utf-8") as list_file:
        for line_number, line in enumerate(list_file, 1):
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue

            elf_path = Path(entry)
            if not elf_path.is_absolute():
                elf_path = root / elf_path
            if not elf_path.is_file():
                raise FileNotFoundError(
                    "ELF listed at {}:{} not found: {}".format(
                        elf_list, line_number, elf_path
                    )
                )
            dii_files.append(elf_path)

    if not dii_files:
        raise RuntimeError("No conflict-free ELF files listed in {}".format(elf_list))

    return dii_files


def run_simulations(root, dii_files, rvfi_max):
    verilator_dir = root / "riscv-implementations" / "cheriot-kudu" / "sim" / "verilator"
    sim_exe = verilator_dir / "obj_dir" / "Vtb_kudu_top"
    results_dir = verilator_dir / "results"

    require_file(sim_exe, "Verilator simulation executable")
    clean_dir(results_dir)

    instr_gnt_wmax  = random.randint(0, 2)
    instr_resp_wmax = random.randint(0, 1)
    data_gnt_wmax   = random.randint(0, 2)
    data_resp_wmax  = random.randint(0, 1)

    print( "Running verilog simulation with WMAX: "
           "INSTR_GNT={}, INSTR_RESP={}, DATA_GNT={}, DATA_RESP={}".format(
        instr_gnt_wmax,
        instr_resp_wmax,
        data_gnt_wmax,
        data_resp_wmax,), flush=True,)


    for dii in sorted(dii_files):
        test_name = dii.stem
        # print("Running verilog simulation for {}".format(test_name))

        # Remove stale logs before each run so missing-output errors are real.
        for log_name in ["rvfi_kudu_core.log", "trace_kudu_core.log"]:
            stale = verilator_dir / log_name
            if stale.exists():
                stale.unlink()

        run_cmd([
            str(sim_exe),
            "+TEST={}".format(test_name),
            "+RVFI_MAX={}".format(rvfi_max),
            "+INSTR_GNT_WMAX={}".format(instr_gnt_wmax),
            "+INSTR_RESP_WMAX={}".format(instr_resp_wmax),
            "+DATA_GNT_WMAX={}".format(data_gnt_wmax),
            "+DATA_RESP_WMAX={}".format(data_resp_wmax),
        ],
            cwd=verilator_dir,
            quiet=True,
        )

        rvfi_log = verilator_dir / "rvfi_kudu_core.log"
        trace_log = verilator_dir / "trace_kudu_core.log"

        require_file(rvfi_log, "simulation RVFI log after test {}".format(test_name))
        require_file(trace_log, "simulation trace log after test {}".format(test_name))

        shutil.move(str(rvfi_log), str(results_dir / "{}.rvfi".format(test_name)))
        shutil.move(str(trace_log), str(results_dir / "{}.trace".format(test_name)))

    return results_dir


def run_remote_vcs_simulations(
    root,
    rvfi_max,
    remote_target,
    remote_dir=REMOTE_VCS_DIR,
    ssh_executable=REMOTE_SSH_EXECUTABLE,
):
    run_dii_dir = (
        root / "riscv-implementations" / "cheriot-kudu" / "sim" / "run_dii"
    )
    bin_dir = run_dii_dir / "bin"
    elf_list = bin_dir / "elfs_no_conflict.list"
    bin_archive = run_dii_dir / "bin.tar.gz"
    results_dir = run_dii_dir / "results"
    results_archive = run_dii_dir / "results.tar.gz"
    remote_results_archive = remote_dir / "results.tar.gz"

    require_dir(run_dii_dir, "Kudu VCS DII working directory")
    require_dir(bin_dir, "Kudu VCS DII ELF directory")
    require_file(elf_list, "conflict-free ELF list")
    require_dir(remote_dir, "remote VCS transfer directory")

    print("\nPackaging VCS inputs for remote simulation ...", flush=True)
    run_cmd(["tar", "-czhf", bin_archive.name, bin_dir.name], cwd=run_dii_dir)
    require_file(bin_archive, "VCS input archive")
    run_cmd(["cp", bin_archive.name, str(remote_dir)], cwd=run_dii_dir)

    remote_command = (
        "zsh -lic 'cd ~/riscdev/super/sim/run_dii && "
        "source ./load_module_vcs && "
        "submit -i ./run_dii_rvfi.py --rvfi_max {} > /dev/null'"
    ).format(rvfi_max)
    print("\nRunning remote VCS simulation ...", flush=True)
    run_cmd(
        [
            str(ssh_executable),
            "-tt",
            remote_target,
            remote_command,
        ],
        cwd=run_dii_dir,
    )

    print("\nCopying remote VCS results back ...", flush=True)
    require_file(remote_results_archive, "remote VCS results archive")
    run_cmd(["cp", str(remote_results_archive), "."], cwd=run_dii_dir)
    require_file(results_archive, "copied VCS results archive")

    clean_dir(results_dir)
    run_cmd(["tar", "-xzf", results_archive.name], cwd=run_dii_dir)
    require_dir(results_dir, "extracted remote VCS results directory")
    if not any(results_dir.glob("*.rvfi")):
        raise RuntimeError("No *.rvfi files found in {}".format(results_dir))

    return results_dir


def find_sim_rvfi(results_dir, test_name):
    candidates = [
        results_dir / "{}.rvfi".format(test_name)
    ]

    for path in candidates:
        if path.is_file():
            return path

    raise FileNotFoundError(
        "Could not find simulation RVFI for {}. Tried: {}".format(
            test_name, ", ".join(str(p) for p in candidates)
        )
    )


def find_reference_rvfi(ref_dir, test_name):
    candidates = [
        ref_dir / "{}_phase2.rvfi".format(test_name),
    ]

    for path in candidates:
        if path.is_file():
            return path

    raise FileNotFoundError(
        "Could not find reference RVFI for {}. Tried: {}".format(
            test_name, ", ".join(str(p) for p in candidates)
        )
    )


def check_results(
    ref_dir,
    results_dir,
    packet_slack,
    rvfi_max,
    relaxed_compare,
    sail_mode,
    supported_csrs,
):
    rvfi_files = sorted(results_dir.glob("*.rvfi"))
    if not rvfi_files:
        raise RuntimeError("No *.rvfi files found in {}".format(results_dir))

    print("Comparing sail results vs verilator ...", flush=True)

    conditional_passes = []

    for sim_rvfi in rvfi_files:
        test_name = sim_rvfi.stem
        ref_rvfi = find_reference_rvfi(ref_dir, test_name)

        sim_packet_count = count_rvfi_packets(sim_rvfi)
        ref_packet_count = count_rvfi_packets(ref_rvfi)
        min_sim_packet_count = min(rvfi_max - 10, ref_packet_count - packet_slack)

        #print("Comparing:")
        #print("  sim: {}".format(sim_rvfi))
        #print("  ref: {}".format(ref_rvfi))
        #print("  sim RVFI packets: {}".format(sim_packet_count))
        #print("  ref RVFI packets: {}".format(ref_packet_count))
        #print("  minimum accepted sim packets: {}".format(min_sim_packet_count))

        if sim_packet_count < min_sim_packet_count:
            print("")
            print("FAIL: Verilator RVFI trace is too short for {}".format(test_name))
            print("  sim packets: {}".format(sim_packet_count))
            print("  ref packets: {}".format(ref_packet_count))
            print("  allowed shortfall: {}".format(packet_slack))
            print("  required sim packets: at least {}".format(min_sim_packet_count))
            raise SystemExit(1)

        ok, packet_index, diff_fields, left_packet, right_packet = compare_rvfi_prefix(sim_rvfi, ref_rvfi)
        if not ok:
            ignore_reason = None
            if relaxed_compare:
                ignore_reason = relaxed_compare_reason(
                    left_packet,
                    right_packet,
                    diff_fields,
                    sail_mode,
                    supported_csrs,
                )

            if ignore_reason is not None:
                conditional_passes.append(test_name)
                print("")
                print("Conditional Pass: ignored RVFI diff for {}".format(test_name))
                print("  parsed packet index: {}".format(packet_index))
                print("  mismatched field(s): {}".format(", ".join(diff_fields)))
                print("  ignore rule: {}".format(ignore_reason))
                # The relaxed rule applies to this first mismatch; do not
                # compare the remainder of this trace.
                continue

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
    fully_passed_count = len(rvfi_files) - len(conditional_passes)
    if conditional_passes:
        print(
            "Conditional PASS: {} test case(s) fully matched, "
            "{} test case(s) matched an RVFI ignore rule: {}".format(
                fully_passed_count,
                len(conditional_passes),
                ", ".join(conditional_passes),
            )
        )
    else:
        print(
            "PASS: {} test case(s) fully matched. Happy! :)".format(
                fully_passed_count
            )
        )


def main():
    parser = argparse.ArgumentParser(
        description="Run CHERIoT TestRIG, Kudu simulations, and RVFI comparison."
    )

    parser.add_argument(
        "--root",
        default=".",
        help="TestRIG repository root. Default: current directory",
    )

    parser.add_argument(
        "--phase1_instr_count",
        type=int,
        default=1000,
        help="Phase-1 generated instruction count. Default: 1000",
    )

    parser.add_argument(
        "--phase2_instr_count",
        "--rvfi_max",
        dest="phase2_instr_count",
        type=int,
        default=None,
        help="Phase-2 Sail instruction limit and Verilog +RVFI_MAX value. "
             "Default: phase1_instr_count",
    )

    parser.add_argument(
        "--packet-slack",
        type=int,
        default=200,
        help="Allowed Verilator RVFI packet shortfall versus Sail. Default: 200",
    )

    parser.add_argument(
        "--case_cnt",
        "--count",
        dest="case_cnt",
        type=int,
        default=100,
        help="Number of TestRIG test cases. Default: 100",
    )

    parser.add_argument(
        "--test",
        default=None,
        help="TestRIG template/test name, for example: caprandom",
    )

    parser.add_argument(
        "--phase1_no_sail",
        "--phase1-no-sail",
        dest="phase1_no_sail",
        action="store_true",
        help="Skip Phase-1 Sail and build trace_*.elf files from the "
             "strrandom traces with build_struct_elf.py",
    )

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--vengine_only",
        "--vengine-only",
        dest="vengine_only",
        action="store_true",
        help="Run only the TestRIG VEngine instruction-trace generator",
    )
    mode_group.add_argument(
        "--phase1_only",
        "--phase1-only",
        dest="phase1_only",
        action="store_true",
        help="Run VEngine generation and Phase-1 ELF generation, then stop",
    )
    mode_group.add_argument(
        "--diff_only",
        "--diff-only",
        dest="diff_only",
        action="store_true",
        help="Skip Phase 1, Phase-2 Sail, and Verilog simulation; only compare "
             "existing Phase-2 outputs",
    )
    mode_group.add_argument(
        "--phase2_only",
        "--phase2-only",
        dest="phase2_only",
        action="store_true",
        help="Reuse existing two_phase_output, run Phase-2 Sail and Verilog "
             "simulation, then compare",
    )
    mode_group.add_argument(
        "--verilog_only",
        "--verilog-only",
        dest="verilog_only",
        action="store_true",
        help="Reuse existing two_phase_output and Phase-2 Sail results, run "
             "only Verilog simulation, then compare",
    )

    parser.add_argument(
        "--sail-mode",
        choices=["cheriot", "rv32"],
        default="cheriot",
        help="Select CHERIoT Sail or standard RV32 sail-riscv. Default: cheriot",
    )

    parser.add_argument(
        "--remote_vcs",
        "--remote-vcs",
        dest="remote_vcs",
        metavar="[USER@]HOST",
        help="Run the Verilog simulation remotely with VCS on [USER@]HOST",
    )

    relaxed_group = parser.add_mutually_exclusive_group()
    relaxed_group.add_argument(
        "--relaxed_compare",
        "--relaxed-compare",
        dest="relaxed_compare",
        action="store_true",
        default=True,
        help="Apply RVFI mismatch ignore rules. Default: enabled",
    )
    relaxed_group.add_argument(
        "--no-relaxed_compare",
        "--no-relaxed-compare",
        dest="relaxed_compare",
        action="store_false",
        help="Disable RVFI mismatch ignore rules",
    )

    args = parser.parse_args()

    if args.phase1_instr_count <= 0:
        parser.error("--phase1_instr_count must be greater than zero")

    if args.phase2_instr_count is None:
        args.phase2_instr_count = args.phase1_instr_count
    elif args.phase2_instr_count <= 0:
        parser.error("--phase2_instr_count must be greater than zero")

    if args.case_cnt <= 0:
        parser.error("--case_cnt must be greater than zero")

    if args.phase1_no_sail:
        if args.sail_mode != "cheriot":
            parser.error("--phase1_no_sail requires --sail-mode cheriot")
        if args.test is None:
            args.test = "strrandom"
        elif args.test != "strrandom":
            parser.error("--phase1_no_sail requires --test strrandom")

    root = Path(args.root).resolve()

    try:
        supported_csrs = (
            SUPPORTED_CSR_ADDRESSES if args.relaxed_compare else frozenset()
        )
        verilator_dir = root / "riscv-implementations" / "cheriot-kudu" / "sim" / "verilator"
        sim_bin = verilator_dir / "bin"
        results_dir = verilator_dir / "results"

        ref_dir = root / "two_phase_output" / "results"

        if args.vengine_only or args.phase1_only:
            run_testrig(
                root=root,
                sail_mode=args.sail_mode,
                case_cnt=args.case_cnt,
                phase1_instr_count=args.phase1_instr_count,
                phase2_instr_count=args.phase2_instr_count,
                test_name=args.test,
                phase1_no_sail=args.phase1_no_sail,
                stop_after="vengine" if args.vengine_only else "phase1",
            )
            return 0

        if args.diff_only:
            require_dir(ref_dir, "existing Phase-2 Sail results directory")
            require_dir(results_dir, "existing simulation results directory")
            check_results(
                ref_dir,
                results_dir,
                args.packet_slack,
                args.phase2_instr_count,
                args.relaxed_compare,
                args.sail_mode,
                supported_csrs,
            )
            return 0

        if args.phase2_only:
            run_phase2_sail(
                root=root,
                sail_mode=args.sail_mode,
                phase2_instr_count=args.phase2_instr_count,
            )
        elif not args.verilog_only:
            run_testrig(
                root=root,
                sail_mode=args.sail_mode,
                case_cnt=args.case_cnt,
                phase1_instr_count=args.phase1_instr_count,
                phase2_instr_count=args.phase2_instr_count,
                test_name=args.test,
                phase1_no_sail=args.phase1_no_sail,
            )
        # sim_bin = prepare_sim_bin(root)
        # ref_dir = prepare_ref_trace(root)
        dii_files = convert_elfs_to_dii(root)

        if args.remote_vcs:
            results_dir = run_remote_vcs_simulations(
                root,
                args.phase2_instr_count,
                args.remote_vcs,
            )
        else:
            results_dir = run_simulations(root, dii_files, args.phase2_instr_count)

        check_results(
            ref_dir,
            results_dir,
            args.packet_slack,
            args.phase2_instr_count,
            args.relaxed_compare,
            args.sail_mode,
            supported_csrs,
        )
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
