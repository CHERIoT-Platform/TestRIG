#!/usr/bin/env python3
#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Generate random RV32 + CHERIoT Xcheri instruction sequences for the
# two-phase execution workflow. Each trace is emitted in *two* formats:
#
#   trace_NNN.hex.txt   Plain-text file with one `0x`-prefixed 32-bit
#                       instruction encoding per line. This is what the
#                       Sail RVFI simulator actually consumes in `-f`
#                       instruction-file mode (see cheriot-sail/RUNNING.md
#                       section 10 "Instruction File Format").
#
#   trace_NNN.S         Human-readable companion file containing the same
#                       instructions as assembly, purely for inspection.
#                       Sail does NOT read this file.
#
# CHERIoT Xcheri encodings are ported directly from the Haskell generator
# used by QuickCheckVEngine:
#   vengines/QuickCheckVEngine/src/RISCV/RV32_Xcheri.hs
# All CHERIoT instructions share the major opcode 0b1011011 (0x5B).

import argparse
import os
import os.path as op
import random
import sys


def auto_pos_int(x):
    val = int(x, 0)
    if val <= 0:
        raise argparse.ArgumentTypeError(
            "argument must be a positive int. Got {:d}.".format(val))
    return val


parser = argparse.ArgumentParser(
    description='Generate random RV32 instruction sequences (hex + .S)')
parser.add_argument('-c', '--count', metavar='N', type=auto_pos_int,
                    default=100,
                    help='Number of instruction sequences to generate (default: 100)')
parser.add_argument('-o', '--output-dir', metavar='DIR', type=str,
                    required=True, help='Output directory for trace files')
parser.add_argument('-a', '--architecture', metavar='ARCH', type=str,
                    default='rv32ecZifencei_Xcheriot',
                    help='Architecture string (informational; '
                         'default: rv32ecZifencei_Xcheriot)')
parser.add_argument('-n', '--num-instructions', metavar='N', type=auto_pos_int,
                    default=50,
                    help='Number of instructions per trace (default: 50)')
parser.add_argument('--qcvengine-path', metavar='PATH', type=str,
                    default=None,
                    help='Ignored; kept for backwards compatibility with '
                         'run_two_phase.sh.')
parser.add_argument('--seed', metavar='SEED', type=int,
                    default=None, help='Random seed for reproducibility')
parser.add_argument('--cheri-weight', type=float, default=0.5,
                    metavar='P',
                    help='Fraction of instructions that should be CHERIoT '
                         'Xcheri cap instructions (0.0–1.0, default: 0.5). '
                         'Ignored when --architecture has no Xcheri.')
parser.add_argument('--no-cheri', action='store_true',
                    help='Disable CHERIoT instructions entirely (RV32I-only).')
args = parser.parse_args()


# ---------------------------------------------------------------------------
# RV32 instruction encoders
# ---------------------------------------------------------------------------

def _r_type(funct7, rs2, rs1, funct3, rd, opcode):
    return ((funct7 & 0x7f) << 25) | ((rs2 & 0x1f) << 20) | \
           ((rs1 & 0x1f) << 15) | ((funct3 & 0x7) << 12) | \
           ((rd & 0x1f) << 7) | (opcode & 0x7f)


def _i_type(imm12, rs1, funct3, rd, opcode):
    return ((imm12 & 0xfff) << 20) | ((rs1 & 0x1f) << 15) | \
           ((funct3 & 0x7) << 12) | ((rd & 0x1f) << 7) | (opcode & 0x7f)


def _u_type(imm20, rd, opcode):
    return ((imm20 & 0xfffff) << 12) | ((rd & 0x1f) << 7) | (opcode & 0x7f)


def _shift_imm(imm, rs1, funct3, rd, funct7):
    # For SLLI/SRLI/SRAI: imm is shamt (5 bits for RV32) plus funct7 in top.
    return (((funct7 & 0x7f) << 25) | ((imm & 0x1f) << 20) |
            ((rs1 & 0x1f) << 15) | ((funct3 & 0x7) << 12) |
            ((rd & 0x1f) << 7) | 0x13)


OP_IMM = 0x13   # ADDI / ANDI / ORI / XORI / SLTI / SLTIU / SLLI / SRLI / SRAI
OP_OP = 0x33    # ADD / SUB / AND / OR / XOR / SLT / SLTU / SLL / SRL / SRA
OP_LUI = 0x37
OP_AUIPC = 0x17


def _rand_reg(avoid_zero=False):
    # RV32E ("embedded") only defines x0..x15; the default CHERIoT arch
    # string "rv32ecZifencei_Xcheriot" is rv32e + c + Zifencei + CHERIoT.
    # Using x16..x31 in that profile raises an illegal-instruction trap,
    # which makes every generated trace fire on its first instruction.
    # Detect the profile from the --architecture string and clamp the
    # register range accordingly.
    arch = args.architecture.lower()
    hi = 15 if ("rv32e" in arch) else 31
    lo = 1 if avoid_zero else 0
    return random.randint(lo, hi)


def _rand_imm12():
    # 12-bit sign-extended immediate. Mask to 12 bits for encoding.
    return random.randint(-2048, 2047) & 0xfff


def _rand_imm20():
    return random.randint(0, 0xfffff)


def _rand_shamt():
    return random.randint(0, 31)


# Each generator returns (encoding, mnemonic) with mnemonic purely
# for the companion .S file. All instructions are guaranteed side-effect
# safe wrt the Sail simulator (no loads/stores or branches — those would
# trap or loop and complicate memory-dump semantics).
def _gen_addi():
    rd, rs1, imm = _rand_reg(True), _rand_reg(), _rand_imm12()
    simm = imm - 0x1000 if imm & 0x800 else imm
    return _i_type(imm, rs1, 0x0, rd, OP_IMM), f"addi x{rd}, x{rs1}, {simm}"


def _gen_andi():
    rd, rs1, imm = _rand_reg(True), _rand_reg(), _rand_imm12()
    simm = imm - 0x1000 if imm & 0x800 else imm
    return _i_type(imm, rs1, 0x7, rd, OP_IMM), f"andi x{rd}, x{rs1}, {simm}"


def _gen_ori():
    rd, rs1, imm = _rand_reg(True), _rand_reg(), _rand_imm12()
    simm = imm - 0x1000 if imm & 0x800 else imm
    return _i_type(imm, rs1, 0x6, rd, OP_IMM), f"ori x{rd}, x{rs1}, {simm}"


def _gen_xori():
    rd, rs1, imm = _rand_reg(True), _rand_reg(), _rand_imm12()
    simm = imm - 0x1000 if imm & 0x800 else imm
    return _i_type(imm, rs1, 0x4, rd, OP_IMM), f"xori x{rd}, x{rs1}, {simm}"


def _gen_slti():
    rd, rs1, imm = _rand_reg(True), _rand_reg(), _rand_imm12()
    simm = imm - 0x1000 if imm & 0x800 else imm
    return _i_type(imm, rs1, 0x2, rd, OP_IMM), f"slti x{rd}, x{rs1}, {simm}"


def _gen_sltiu():
    rd, rs1, imm = _rand_reg(True), _rand_reg(), _rand_imm12()
    return _i_type(imm, rs1, 0x3, rd, OP_IMM), f"sltiu x{rd}, x{rs1}, {imm}"


def _gen_slli():
    rd, rs1, sh = _rand_reg(True), _rand_reg(), _rand_shamt()
    return _shift_imm(sh, rs1, 0x1, rd, 0x00), f"slli x{rd}, x{rs1}, {sh}"


def _gen_srli():
    rd, rs1, sh = _rand_reg(True), _rand_reg(), _rand_shamt()
    return _shift_imm(sh, rs1, 0x5, rd, 0x00), f"srli x{rd}, x{rs1}, {sh}"


def _gen_srai():
    rd, rs1, sh = _rand_reg(True), _rand_reg(), _rand_shamt()
    return _shift_imm(sh, rs1, 0x5, rd, 0x20), f"srai x{rd}, x{rs1}, {sh}"


def _gen_add():
    rd, rs1, rs2 = _rand_reg(True), _rand_reg(), _rand_reg()
    return _r_type(0x00, rs2, rs1, 0x0, rd, OP_OP), f"add x{rd}, x{rs1}, x{rs2}"


def _gen_sub():
    rd, rs1, rs2 = _rand_reg(True), _rand_reg(), _rand_reg()
    return _r_type(0x20, rs2, rs1, 0x0, rd, OP_OP), f"sub x{rd}, x{rs1}, x{rs2}"


def _gen_sll():
    rd, rs1, rs2 = _rand_reg(True), _rand_reg(), _rand_reg()
    return _r_type(0x00, rs2, rs1, 0x1, rd, OP_OP), f"sll x{rd}, x{rs1}, x{rs2}"


def _gen_slt():
    rd, rs1, rs2 = _rand_reg(True), _rand_reg(), _rand_reg()
    return _r_type(0x00, rs2, rs1, 0x2, rd, OP_OP), f"slt x{rd}, x{rs1}, x{rs2}"


def _gen_sltu():
    rd, rs1, rs2 = _rand_reg(True), _rand_reg(), _rand_reg()
    return _r_type(0x00, rs2, rs1, 0x3, rd, OP_OP), f"sltu x{rd}, x{rs1}, x{rs2}"


def _gen_xor():
    rd, rs1, rs2 = _rand_reg(True), _rand_reg(), _rand_reg()
    return _r_type(0x00, rs2, rs1, 0x4, rd, OP_OP), f"xor x{rd}, x{rs1}, x{rs2}"


def _gen_srl():
    rd, rs1, rs2 = _rand_reg(True), _rand_reg(), _rand_reg()
    return _r_type(0x00, rs2, rs1, 0x5, rd, OP_OP), f"srl x{rd}, x{rs1}, x{rs2}"


def _gen_sra():
    rd, rs1, rs2 = _rand_reg(True), _rand_reg(), _rand_reg()
    return _r_type(0x20, rs2, rs1, 0x5, rd, OP_OP), f"sra x{rd}, x{rs1}, x{rs2}"


def _gen_or():
    rd, rs1, rs2 = _rand_reg(True), _rand_reg(), _rand_reg()
    return _r_type(0x00, rs2, rs1, 0x6, rd, OP_OP), f"or x{rd}, x{rs1}, x{rs2}"


def _gen_and():
    rd, rs1, rs2 = _rand_reg(True), _rand_reg(), _rand_reg()
    return _r_type(0x00, rs2, rs1, 0x7, rd, OP_OP), f"and x{rd}, x{rs1}, x{rs2}"


def _gen_lui():
    rd, imm = _rand_reg(True), _rand_imm20()
    return _u_type(imm, rd, OP_LUI), f"lui x{rd}, 0x{imm:x}"


def _gen_auipc():
    rd, imm = _rand_reg(True), _rand_imm20()
    return _u_type(imm, rd, OP_AUIPC), f"auipc x{rd}, 0x{imm:x}"


GENERATORS = [
    _gen_addi, _gen_andi, _gen_ori, _gen_xori,
    _gen_slti, _gen_sltiu,
    _gen_slli, _gen_srli, _gen_srai,
    _gen_add, _gen_sub, _gen_sll, _gen_slt, _gen_sltu,
    _gen_xor, _gen_srl, _gen_sra, _gen_or, _gen_and,
    _gen_lui, _gen_auipc,
]


# ---------------------------------------------------------------------------
# CHERIoT Xcheri encoders (port of vengines/QuickCheckVEngine/src/RISCV/
# RV32_Xcheri.hs). All instructions use major opcode 0b1011011 (0x5B).
# ---------------------------------------------------------------------------

CHERI_OP = 0x5B


def _xcheri_inspect(funct5, rd, cs1):
    """funct7=1111111, funct5[4:0], cs1, funct3=000, rd, opcode=1011011."""
    return ((0x7f & 0x7f) << 25) | ((funct5 & 0x1f) << 20) | \
           ((cs1 & 0x1f) << 15) | (0x0 << 12) | \
           ((rd & 0x1f) << 7) | CHERI_OP


def _xcheri_r(funct7, src2, cs1, cd):
    """funct7, rs2/cs2, cs1, funct3=000, cd, opcode=1011011."""
    return ((funct7 & 0x7f) << 25) | ((src2 & 0x1f) << 20) | \
           ((cs1 & 0x1f) << 15) | (0x0 << 12) | \
           ((cd & 0x1f) << 7) | CHERI_OP


def _xcheri_i(imm12, cs1, funct3, cd):
    """imm[11:0], cs1, funct3, cd, opcode=1011011 (cincaddrimm / csetboundsimm)."""
    return ((imm12 & 0xfff) << 20) | ((cs1 & 0x1f) << 15) | \
           ((funct3 & 0x7) << 12) | ((cd & 0x1f) << 7) | CHERI_OP


# Capability inspection (funct5 selects op; all write an integer result to rd).
def _gen_cgetperm():
    rd, cs1 = _rand_reg(True), _rand_reg()
    return _xcheri_inspect(0x00, rd, cs1), f"cgetperm x{rd}, c{cs1}"

def _gen_cgettype():
    rd, cs1 = _rand_reg(True), _rand_reg()
    return _xcheri_inspect(0x01, rd, cs1), f"cgettype x{rd}, c{cs1}"

def _gen_cgetbase():
    rd, cs1 = _rand_reg(True), _rand_reg()
    return _xcheri_inspect(0x02, rd, cs1), f"cgetbase x{rd}, c{cs1}"

def _gen_cgetlen():
    rd, cs1 = _rand_reg(True), _rand_reg()
    return _xcheri_inspect(0x03, rd, cs1), f"cgetlen x{rd}, c{cs1}"

def _gen_cgettag():
    rd, cs1 = _rand_reg(True), _rand_reg()
    return _xcheri_inspect(0x04, rd, cs1), f"cgettag x{rd}, c{cs1}"

def _gen_cgetaddr():
    rd, cs1 = _rand_reg(True), _rand_reg()
    return _xcheri_inspect(0x0f, rd, cs1), f"cgetaddr x{rd}, c{cs1}"

def _gen_cgethigh():
    rd, cs1 = _rand_reg(True), _rand_reg()
    return _xcheri_inspect(0x17, rd, cs1), f"cgethigh x{rd}, c{cs1}"

def _gen_cgettop():
    rd, cs1 = _rand_reg(True), _rand_reg()
    return _xcheri_inspect(0x18, rd, cs1), f"cgettop x{rd}, c{cs1}"

# cmove: funct5=0x0a, copies cs1 → cd.
def _gen_cmove():
    cd, cs1 = _rand_reg(True), _rand_reg()
    return _xcheri_inspect(0x0a, cd, cs1), f"cmove c{cd}, c{cs1}"

# ccleartag: funct5=0x0b, strips tag.
def _gen_ccleartag():
    cd, cs1 = _rand_reg(True), _rand_reg()
    return _xcheri_inspect(0x0b, cd, cs1), f"ccleartag c{cd}, c{cs1}"

# Capability arithmetic / modification (R-type in CHERI space, funct3=000).
def _gen_csub():
    cd, cs1, cs2 = _rand_reg(True), _rand_reg(), _rand_reg()
    return _xcheri_r(0x14, cs2, cs1, cd), f"csub x{cd}, c{cs1}, c{cs2}"

def _gen_cincaddr():
    cd, cs1, rs2 = _rand_reg(True), _rand_reg(), _rand_reg()
    return _xcheri_r(0x11, rs2, cs1, cd), f"cincaddr c{cd}, c{cs1}, x{rs2}"

def _gen_csetaddr():
    cd, cs1, rs2 = _rand_reg(True), _rand_reg(), _rand_reg()
    return _xcheri_r(0x10, rs2, cs1, cd), f"csetaddr c{cd}, c{cs1}, x{rs2}"

def _gen_csethigh():
    cd, cs1, rs2 = _rand_reg(True), _rand_reg(), _rand_reg()
    return _xcheri_r(0x16, rs2, cs1, cd), f"csethigh c{cd}, c{cs1}, x{rs2}"

def _gen_csetbounds():
    cd, cs1, rs2 = _rand_reg(True), _rand_reg(), _rand_reg()
    return _xcheri_r(0x08, rs2, cs1, cd), f"csetbounds c{cd}, c{cs1}, x{rs2}"

def _gen_csetboundsexact():
    cd, cs1, rs2 = _rand_reg(True), _rand_reg(), _rand_reg()
    return _xcheri_r(0x09, rs2, cs1, cd), f"csetboundsexact c{cd}, c{cs1}, x{rs2}"

def _gen_candperm():
    cd, cs1, rs2 = _rand_reg(True), _rand_reg(), _rand_reg()
    return _xcheri_r(0x0d, rs2, cs1, cd), f"candperm c{cd}, c{cs1}, x{rs2}"

# Assertions (write 0/1 to rd).
def _gen_ctestsubset():
    rd, cs1, cs2 = _rand_reg(True), _rand_reg(), _rand_reg()
    return _xcheri_r(0x20, cs2, cs1, rd), f"ctestsubset x{rd}, c{cs1}, c{cs2}"

def _gen_csetequalexact():
    rd, cs1, cs2 = _rand_reg(True), _rand_reg(), _rand_reg()
    return _xcheri_r(0x21, cs2, cs1, rd), f"csetequalexact x{rd}, c{cs1}, c{cs2}"

# I-type capability operations.
def _gen_cincaddrimm():
    cd, cs1, imm = _rand_reg(True), _rand_reg(), _rand_imm12()
    simm = imm - 0x1000 if imm & 0x800 else imm
    return _xcheri_i(imm, cs1, 0x1, cd), f"cincaddrimm c{cd}, c{cs1}, {simm}"

def _gen_csetboundsimm():
    cd, cs1, imm = _rand_reg(True), _rand_reg(), _rand_imm12()
    # Unsigned in the ISA; emit as-is.
    return _xcheri_i(imm, cs1, 0x2, cd), f"csetboundsimm c{cd}, c{cs1}, {imm}"


CHERI_GENERATORS = [
    _gen_cgetperm, _gen_cgettype, _gen_cgetbase, _gen_cgetlen,
    _gen_cgettag, _gen_cgetaddr, _gen_cgethigh, _gen_cgettop,
    _gen_cmove, _gen_ccleartag,
    _gen_csub, _gen_cincaddr, _gen_csetaddr, _gen_csethigh,
    _gen_csetbounds, _gen_csetboundsexact, _gen_candperm,
    _gen_ctestsubset, _gen_csetequalexact,
    _gen_cincaddrimm, _gen_csetboundsimm,
]


def _cheri_enabled():
    if args.no_cheri:
        return False
    arch = args.architecture.lower()
    return ('xcheri' in arch) or ('xcheriot' in arch)


def generate_instruction():
    if _cheri_enabled() and random.random() < args.cheri_weight:
        return random.choice(CHERI_GENERATORS)()
    return random.choice(GENERATORS)()


# EBREAK terminator = 0x00100073. This gives Sail a clean halt point so
# the memory dump can settle after the random stream executes.
EBREAK = 0x00100073


def generate_trace_files(hex_path, s_path, num_instructions, arch):
    with open(hex_path, 'w') as fh, open(s_path, 'w') as fs:
        fh.write(f"# Auto-generated RV32 instruction hex file "
                 f"({num_instructions} instrs, arch={arch})\n")
        fh.write("# Consumed by cheri_riscv_rvfi_RV32 -f <this_file>\n")
        fs.write(f"# Auto-generated assembly companion "
                 f"({num_instructions} instrs)\n")
        fs.write(".section .text\n")
        fs.write(".globl _start\n_start:\n")

        for _ in range(num_instructions):
            enc, mnem = generate_instruction()
            fh.write(f"0x{enc:08x}    # {mnem}\n")
            fs.write(f"    {mnem}\n")

        # Terminator so the Sail simulator stops cleanly and dumps memory.
        fh.write(f"0x{EBREAK:08x}    # ebreak (terminator)\n")
        fs.write("    ebreak\n")


def main():
    if args.seed is not None:
        random.seed(args.seed)

    os.makedirs(args.output_dir, exist_ok=True)

    print(f"Generating {args.count} instruction sequences...")
    print(f"  Architecture:      {args.architecture}")
    print(f"  Output directory:  {args.output_dir}")
    print(f"  Instructions/trace: {args.num_instructions}")
    if args.seed is not None:
        print(f"  Random seed:       {args.seed}")

    success = 0
    for i in range(args.count):
        n = i + 1
        hex_file = op.join(args.output_dir, f"trace_{n:03d}.hex.txt")
        s_file = op.join(args.output_dir, f"trace_{n:03d}.S")
        try:
            generate_trace_files(hex_file, s_file,
                                 args.num_instructions, args.architecture)
            success += 1
            if n % 10 == 0 or n == args.count:
                print(f"  Generated {n}/{args.count} traces...")
        except Exception as e:
            print(f"  ERROR generating trace {n}: {e}", file=sys.stderr)

    print(f"\nBatch generation complete!")
    print(f"  Success: {success}/{args.count}")
    return 0 if success == args.count else 1


if __name__ == '__main__':
    sys.exit(main())
