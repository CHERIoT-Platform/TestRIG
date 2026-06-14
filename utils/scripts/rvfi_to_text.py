#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""
Decode Sail's binary RVFI v1 trace (``--rvfi-output <file>``) to a
verbose, labeled text format — one instruction per record with every
RVFI field on its own line, plus a lightweight mnemonic hint.

The custom CHERIoT v1 on-wire layout used by this script is
93 bytes/packet.  It keeps every field byte-aligned and widens the
capability-capable data fields to 72 bits / 9 bytes.

  bytes 0-7    order      u64 LE
  bytes 8-15   pc_rdata   u64 LE
  bytes 16-23  pc_wdata   u64 LE
  bytes 24-31  insn       u64 LE  (low 32 bits hold the instruction)
  bytes 32-40  rs1_rdata  u72 LE  (bits 71:65 padding, bit 64 tag, bits 63:0 payload)
  bytes 41-49  rs2_rdata  u72 LE
  bytes 50-58  rd_wdata   u72 LE
  bytes 59-66  mem_addr   u64 LE
  bytes 67-75  mem_rdata  u72 LE
  bytes 76-84  mem_wdata  u72 LE
  byte 85      mem_rmask  u8    (one bit per byte of mem_rdata payload)
  byte 86      mem_wmask  u8    (one bit per byte of mem_wdata payload)
  byte 87      rs1_addr   u8
  byte 88      rs2_addr   u8
  byte 89      rd_addr    u8
  byte 90      trap       u8
  byte 91      halt       u8
  byte 92      intr       u8

A halt packet (``halt != 0``) is written once at end-of-stream.
"""

from __future__ import annotations

import argparse
import os.path as op
import sys

PACKET_SIZE = 93
U72_MASK = (1 << 72) - 1
U64_MASK = (1 << 64) - 1
U32_MASK = (1 << 32) - 1


def _le_int(buf: bytes, off: int, size: int) -> int:
    return int.from_bytes(buf[off:off + size], byteorder='little', signed=False)


def _fmt_u72(v: int) -> str:
    return f'0x{v & U72_MASK:018x}'


def _fmt_u64(v: int) -> str:
    return f'0x{v & U64_MASK:016x}'


def _fmt_u32(v: int) -> str:
    return f'0x{v & U32_MASK:08x}'



# ---------------------------------------------------------------------------
# Mnemonic hint — best-effort, covers the ISA subset the testrig emits.
# ---------------------------------------------------------------------------
_RV_OP_IMM   = 0b0010011
_RV_OP       = 0b0110011
_RV_LUI      = 0b0110111
_RV_AUIPC    = 0b0010111
_RV_JAL      = 0b1101111
_RV_JALR     = 0b1100111
_RV_BRANCH   = 0b1100011
_RV_LOAD     = 0b0000011
_RV_STORE    = 0b0100011
_RV_MISCMEM  = 0b0001111
_RV_SYSTEM   = 0b1110011
_RV_CHERIOT  = 0b1011011   # Xcheri major opcode

_OPIMM_F3 = {
    0b000: 'addi', 0b010: 'slti', 0b011: 'sltiu',
    0b100: 'xori', 0b110: 'ori',  0b111: 'andi',
    0b001: 'slli',
    0b101: 'srli/srai',
}
_OP_F3 = {
    (0b000, 0b0000000): 'add', (0b000, 0b0100000): 'sub',
    (0b001, 0b0000000): 'sll',
    (0b010, 0b0000000): 'slt', (0b011, 0b0000000): 'sltu',
    (0b100, 0b0000000): 'xor',
    (0b101, 0b0000000): 'srl', (0b101, 0b0100000): 'sra',
    (0b110, 0b0000000): 'or',  (0b111, 0b0000000): 'and',
}
_BRANCH_F3 = {
    0b000: 'beq', 0b001: 'bne',
    0b100: 'blt', 0b101: 'bge',
    0b110: 'bltu', 0b111: 'bgeu',
}
_LOAD_F3  = {0b000: 'lb', 0b001: 'lh', 0b010: 'lw', 0b100: 'lbu', 0b101: 'lhu'}
_STORE_F3 = {0b000: 'sb', 0b001: 'sh', 0b010: 'sw'}

# CHERIoT Xcheri decode tables (major opcode 0x5B = 0b1011011, funct3=0).
# All bit patterns ported directly from
# vengines/QuickCheckVEngine/src/RISCV/RV32_Xcheri.hs (the *_raw lines).
#
# Inspection ops: encoded as `1111111 funct5 cs1 000 rd 1011011`, so
# funct7 == 0x7f and the funct5 field overlaps the rs2 position.
_XCHERI_INSPECT_F5 = {
    0x00: 'cgetperm',  0x01: 'cgettype', 0x02: 'cgetbase',
    0x03: 'cgetlen',   0x04: 'cgettag',
    0x0a: 'cmove',     0x0b: 'ccleartag',
    0x0f: 'cgetaddr',  0x12: 'cloadtags',
    0x17: 'cgethigh',  0x18: 'cgettop',
}
# R-type ops: encoded as `funct7 rs2/cs2/cSP cs1 000 cd 1011011`.
# Distinguished by funct7 (bits[31:25]).
_XCHERI_R_F7 = {
    0x01: 'cspecialrw',         # encoded `0000001 cSP cs1 000 cd …`
    0x08: 'csetbounds',         # `0001000 rs2 cs1 000 cd …`
    0x09: 'csetboundsexact',    # `0001001 rs2 cs1 000 cd …`
    0x0b: 'cseal',              # `0001011 cs2 cs1 000 cd …`
    0x0c: 'cunseal',            # `0001100 cs2 cs1 000 cd …`
    0x0d: 'candperm',           # `0001101 rs2 cs1 000 cd …`
    0x10: 'csetaddr',           # `0010000 rs2 cs1 000 cd …`
    0x11: 'cincaddr',           # `0010001 rs2 cs1 000 cd …`
    0x14: 'csub',               # `0010100 cs2 cs1 000 cd …`
    0x16: 'csethigh',           # `0010110 rs2 cs1 000 cd …`
    0x20: 'ctestsubset',        # `0100000 cs2 cs1 000 rd …`
    0x21: 'csetequalexact',     # `0100001 cs2 cs1 000 rd …`
}
# cspecialrw's rs2 field is an SCR (special capability register)
# *index*, not a regular GPR number. Pretty-print it with the SCR name
# instead of `x{n}` so the output matches what Sail's log emits.
_XCHERI_SCR_NAMES = {
    0: 'pcc',    1: 'ddc',
    4: 'utcc',   5: 'utdc',   6: 'uscratchc',  7: 'uepcc',
    12: 'stcc',  13: 'stdc',  14: 'sscratchc', 15: 'sepcc',
    28: 'mtcc',  29: 'mtdc',  30: 'mscratchc', 31: 'mepcc',
}


def _mnemonic(insn: int) -> str:
    """Best-effort mnemonic hint for a 32-bit insn."""
    if insn == 0:
        return '<zero>'
    opcode = insn & 0x7f
    rd     = (insn >> 7)  & 0x1f
    f3     = (insn >> 12) & 0x7
    rs1    = (insn >> 15) & 0x1f
    rs2    = (insn >> 20) & 0x1f
    f7     = (insn >> 25) & 0x7f
    imm_i  = _sext((insn >> 20) & 0xfff, 12)

    if opcode == _RV_OP_IMM:
        m = _OPIMM_F3.get(f3, f'op-imm.f3={f3}')
        return f'{m} x{rd}, x{rs1}, {imm_i}'
    if opcode == _RV_OP:
        m = _OP_F3.get((f3, f7), f'op.f3={f3},f7=0x{f7:02x}')
        return f'{m} x{rd}, x{rs1}, x{rs2}'
    if opcode == _RV_LUI:
        return f'lui x{rd}, 0x{(insn >> 12) & 0xfffff:05x}'
    if opcode == _RV_AUIPC:
        return f'auipc x{rd}, 0x{(insn >> 12) & 0xfffff:05x}'
    if opcode == _RV_JAL:
        return f'jal x{rd}, <imm>'
    if opcode == _RV_JALR:
        return f'jalr x{rd}, x{rs1}, {imm_i}'
    if opcode == _RV_BRANCH:
        m = _BRANCH_F3.get(f3, f'branch.f3={f3}')
        return f'{m} x{rs1}, x{rs2}, <imm>'
    if opcode == _RV_LOAD:
        m = _LOAD_F3.get(f3, f'load.f3={f3}')
        return f'{m} x{rd}, {imm_i}(x{rs1})'
    if opcode == _RV_STORE:
        m = _STORE_F3.get(f3, f'store.f3={f3}')
        return f'{m} x{rs2}, <imm>(x{rs1})'
    if opcode == _RV_MISCMEM:
        return 'fence' if f3 == 0 else 'fence.i' if f3 == 1 else f'miscmem.f3={f3}'
    if opcode == _RV_SYSTEM:
        if f3 == 0 and (insn >> 20) == 0:
            return 'ecall'
        if f3 == 0 and (insn >> 20) == 1:
            return 'ebreak'
        return f'system.f3={f3}'
    if opcode == _RV_CHERIOT:
        if f3 == 0 and f7 == 0x7f:
            f5 = rs2  # the funct5 field overlaps the rs2 position
            m = _XCHERI_INSPECT_F5.get(f5, f'cheriot.inspect.f5=0x{f5:02x}')
            # cgetperm / cgettype / cgetbase / cgetlen / cgettag /
            # cgetaddr / cgethigh / cgetsealed write an integer rd.
            # cmove / ccleartag / cgettop / cloadtags write a capability cd.
            if m in {'cmove', 'ccleartag', 'cgettop', 'cloadtags'}:
                return f'{m} cx{rd}, cx{rs1}'
            return f'{m} x{rd}, cx{rs1}'
        if f3 == 0:
            m = _XCHERI_R_F7.get(f7, f'cheriot.r.f7=0x{f7:02x}')
            # cspecialrw's rs2 is an SCR index, not a register. Pretty-
            # print with the SCR name so the line matches Sail's own
            # disassembly (e.g. "cspecialrw ca5, mscratchc, cnull").
            if m == 'cspecialrw':
                scr = _XCHERI_SCR_NAMES.get(rs2, f'scr{rs2}')
                return f'cspecialrw cx{rd}, {scr}, cx{rs1}'
            # ctestsubset and csetequalexact write an integer rd; the
            # rest write a capability cd. Both forms read cs1; the
            # third operand is rs2 (integer) for the "set-from-int"
            # ops and cs2 (capability) for the rest.
            int_rd_ops  = {'ctestsubset', 'csetequalexact'}
            int_rs2_ops = {'csetbounds', 'csetboundsexact',
                           'candperm', 'csetaddr', 'cincaddr', 'csethigh'}
            d_pfx = 'x' if m in int_rd_ops else 'cx'
            r_pfx = 'x' if m in int_rs2_ops else 'cx'
            return f'{m} {d_pfx}{rd}, cx{rs1}, {r_pfx}{rs2}'
        if f3 == 1:
            return f'cincaddrimm cx{rd}, cx{rs1}, {imm_i}'
        if f3 == 2:
            return f'csetboundsimm cx{rd}, cx{rs1}, {imm_i & 0xfff}'
        return f'cheriot.f3={f3}'
    return f'opcode=0x{opcode:02x}'


def _sext(x: int, bits: int) -> int:
    """Sign-extend a ``bits``-wide unsigned value to a Python int."""
    m = 1 << (bits - 1)
    return (x ^ m) - m


# ---------------------------------------------------------------------------
# Packet decode + render.
# ---------------------------------------------------------------------------
def decode_packet(buf: bytes) -> dict:
    if len(buf) != PACKET_SIZE:
        raise ValueError(f'RVFI v1 packet must be {PACKET_SIZE} bytes, '
                         f'got {len(buf)}')
    return {
        'order': _le_int(buf, 0, 8),
        'pc_rdata': _le_int(buf, 8, 8),
        'pc_wdata': _le_int(buf, 16, 8),
        'insn': _le_int(buf, 24, 8) & U32_MASK,

        # 72-bit byte-aligned data fields.  For capability values:
        #   bits 71:65 = zero padding
        #   bit  64    = tag
        #   bits 63:0  = payload
        'rs1_rdata': _le_int(buf, 32, 9),
        'rs2_rdata': _le_int(buf, 41, 9),
        'rd_wdata': _le_int(buf, 50, 9),

        'mem_addr': _le_int(buf, 59, 8),
        'mem_rdata': _le_int(buf, 67, 9),
        'mem_wdata': _le_int(buf, 76, 9),

        'mem_rmask': buf[85],
        'mem_wmask': buf[86],
        'rs1_addr': buf[87],
        'rs2_addr': buf[88],
        'rd_addr': buf[89],
        'trap': buf[90],
        'halt': buf[91],
        'intr': buf[92],
    }


def _mask_bits(m: int) -> str:
    """Pretty-print an 8-bit byte-mask as ``0b00001111`` with a byte count."""
    set_bits = bin(m & 0xff).count('1')
    return f'0b{m & 0xff:08b} ({set_bits} byte(s))'


# Instructions where bits[19:15] are NOT a real rs1 — don't decode rs1 from
# the encoding for these (LUI / AUIPC / JAL have only rd + imm; FENCE has
# no source regs in the conventional sense).
_NO_RS1 = {0x37, 0x17, 0x6f}              # LUI / AUIPC / JAL
# Instructions whose bits[24:20] are NOT rs2: I-type (loads, ALU-imm,
# JALR, SYSTEM, FENCE), U-type, J-type, and CHERIoT's Xcheri opcode.
_NO_RS2 = {0x03, 0x13, 0x67, 0x73, 0x0f,  # LOAD / OP-IMM / JALR / SYSTEM / FENCE
           0x37, 0x17, 0x6f}              # LUI / AUIPC / JAL
#           0x37, 0x17, 0x6f, 0x5b}        # LUI / AUIPC / JAL / Xcheri


def _decode_regs(insn32: int) -> dict:
    """Pull rs1 / rs2 / rd from the instruction encoding.

    Sail's RVFI exec packet currently leaves rs1_addr / rs2_addr (and
    their _rdata counterparts) at zero — it only populates rd_addr.
    The instruction encoding itself is the source of truth for which
    registers the instruction reads, so we recover them here.
    """
    opcode = insn32 & 0x7f
    rd  = (insn32 >> 7) & 0x1f
    rs1 = (insn32 >> 15) & 0x1f
    rs2 = (insn32 >> 20) & 0x1f
    has_rs1 = opcode not in _NO_RS1
    has_rs2 = opcode not in _NO_RS2
    return {'rd': rd, 'rs1': rs1, 'rs2': rs2,
            'has_rs1': has_rs1, 'has_rs2': has_rs2}


def render_packet(p: dict, idx: int) -> str:
    if p['halt'] != 0:
        return (f'# --- RVFI packet {idx} (halt) ---\n'
                f'order     : {p["order"]}\n'
                f'halt      : 0x{p["halt"]:02x}\n'
                f'trap      : 0x{p["trap"]:02x}\n'
                f'intr      : 0x{p["intr"]:02x}\n')
    mnem = _mnemonic(p['insn'])
    decoded = _decode_regs(p['insn'])

    # Display source/destination register numbers from the packet.
    # _decode_regs() is still used only to decide whether a source register
    # position exists for this instruction class, and for the mnemonic hint.
    rs1, rs2 = p['rs1_addr'], p['rs2_addr']

    # PC/mem_addr are rendered as 32-bit addresses for this RV32 build.
    # Data fields are rendered as full 72-bit values so the CHERIoT tag bit
    # remains visible: bits 71:65 are padding, bit 64 is tag, bits 63:0 are
    # the payload/value.
    out = [
        f'# --- RVFI packet {idx} ---',
        f'order     : {p["order"]}',
        f'halt      : 0x{p["halt"]:02x}',
        f'trap      : 0x{p["trap"]:02x}',
        f'intr      : 0x{p["intr"]:02x}',
        f'pc_rdata  : {_fmt_u32(p["pc_rdata"])}',
        f'pc_wdata  : {_fmt_u32(p["pc_wdata"])}',
        f'insn      : 0x{p["insn"]:08x}  ; {mnem}',
    ]
    # rs1 / rs2 lines: omit if the instruction has no source reg of
    # that position (LUI/AUIPC/JAL have no rs1; I-type / U-type have
    # no rs2).
    if decoded['has_rs1']:
        out.append(f'rs1       : x{rs1:02d}  rdata={_fmt_u72(p["rs1_rdata"])}')
    if decoded['has_rs2']:
        out.append(f'rs2       : x{rs2:02d}  rdata={_fmt_u72(p["rs2_rdata"])}')
    # rd line: show the packet's rd_addr (Sail populates this correctly
    # and 0 means "no write committed" — matches RVFI semantics).
    out.append(f'rd        : x{p["rd_addr"]:02d}  wdata={_fmt_u72(p["rd_wdata"])}')
    out += [
        f'mem_addr  : {_fmt_u32(p["mem_addr"])}',
        f'mem_rmask : {_mask_bits(p["mem_rmask"])}',
        f'mem_rdata : {_fmt_u72(p["mem_rdata"])}',
        f'mem_wmask : {_mask_bits(p["mem_wmask"])}',
        f'mem_wdata : {_fmt_u72(p["mem_wdata"])}',
    ]
    return '\n'.join(out) + '\n'


# ---------------------------------------------------------------------------
# Driver.
# ---------------------------------------------------------------------------
def convert(path_in: str, path_out: str, *, strict: bool = True) -> int:
    with open(path_in, 'rb') as f:
        data = f.read()
    if len(data) == 0:
        raise ValueError(f'empty RVFI binary: {path_in}')
    if len(data) % PACKET_SIZE != 0:
        msg = (f'{path_in}: length {len(data)} is not a multiple of '
               f'{PACKET_SIZE} (v1 packet size)')
        if strict:
            raise ValueError(msg)
        sys.stderr.write(f'WARNING: {msg}; truncating\n')
        data = data[:(len(data) // PACKET_SIZE) * PACKET_SIZE]
    n = len(data) // PACKET_SIZE
    with open(path_out, 'w') as f:
        f.write(f'# RVFI v1 text trace — decoded from {op.basename(path_in)}\n')
        f.write(f'# {n} packet(s), {PACKET_SIZE} bytes each (see rvfi_to_text.py for schema)\n')
        f.write('#\n')
        f.write('# Display notes:\n')
        f.write('#   pc/mem_addr:         shown as 32-bit addresses for RV32 readability\n')
        f.write('#   rs*/rd/mem data:    shown as full 72-bit byte-aligned fields\n')
        f.write('#                       bits 71:65 are padding, bit 64 is tag,\n')
        f.write('#                       bits 63:0 are the payload/value.\n')
        f.write('#   rs1 / rs2 / rd:     register numbers are from the packet fields.\n')
        f.write('#   rs1_rdata/rs2_rdata: raw 72-bit packet fields.\n')
        f.write('#   rd_addr:            from the packet. 0 means "no write committed"\n')
        f.write('#                       (true rd=x0, or trap suppressed the write).\n')
        f.write('#\n')
        for i in range(n):
            p = decode_packet(data[i * PACKET_SIZE:(i + 1) * PACKET_SIZE])
            f.write(render_packet(p, i))
            f.write('\n')
    return n


def parse_args():
    p = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    p.add_argument('--input', required=True,
                   help='binary RVFI v1 trace file (or - for stdin)')
    p.add_argument('--output', required=True,
                   help='destination text file (or - for stdout)')
    p.add_argument('--lenient', action='store_true',
                   help='truncate partial trailing packet instead of erroring')
    return p.parse_args()


def main():
    args = parse_args()
    try:
        n = convert(args.input, args.output, strict=not args.lenient)
    except (OSError, ValueError) as e:
        print(f'ERROR: {e}', file=sys.stderr)
        return 1
    print(f'Decoded {n} RVFI packet(s) -> {args.output}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
