#!/usr/bin/env python3
"""Generate Phase-2 .addata files from Phase-1 ELF metadata."""

import argparse
import random
import struct
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile


ADDATA_SECTION = ".addata_info"
# IT8 decodes nonzero cE with XOR 0x1f; encoded values for exponents
# 0x19 through 0x1e are therefore forbidden.
FORBIDDEN_TAGGED_CE = frozenset(
    exponent ^ 0x1f for exponent in range(0x19, 0x1f)
)
ALLOWED_TAGGED_CE = tuple(
    value for value in range(0x20) if value not in FORBIDDEN_TAGGED_CE
)
CAP_BASE_MASK = (1 << 33) - 1


def read_addata_info(elf_path):
    """Return (aligned start address, entry count), or None if absent."""
    with elf_path.open("rb") as elf_file:
        section = ELFFile(elf_file).get_section_by_name(ADDATA_SECTION)
        if section is None:
            return None
        data = section.data()

    if len(data) != 8:
        raise ValueError("{} must contain 8 bytes".format(ADDATA_SECTION))
    offset, size = struct.unpack("<II", data)
    if offset & 7:
        raise ValueError("additional-data offset is not 8-byte aligned")
    if size > 0x3ff:
        raise ValueError("additional-data entry count exceeds 0x3ff")
    if size and offset + (size - 1) * 8 > 0xfffffff8:
        raise ValueError("additional-data area exceeds 32-bit addressing")
    return offset, size


def decode_cap_base(data):
    """Decode the 33-bit capability base using the CHERIoT Sail algorithm."""
    encoded_exponent = (data >> 49) & 0x1f
    exponent = 0 if encoded_exponent == 0 else encoded_exponent ^ 0x1f
    base_mantissa = (data >> 32) & 0x1ff
    address = data & 0xffffffff

    address_mid = (address >> exponent) & 0x1ff
    address_high = address >> (exponent + 9)
    base_correction = 1 if address_mid < base_mantissa else 0

    return (((address_high - base_correction) << 9 | base_mantissa)
            << exponent) & CAP_BASE_MASK


def random_addata_value():
    """Generate one 65-bit value, constraining tagged values to IT8."""
    tag = random.getrandbits(1)
    data = random.getrandbits(64)
    if tag:
        data &= ~(1 << 63)
        data &= ~(0x7 << 54)
        data |= random.randrange(6) << 54
        data &= ~(0x1f << 49)
        data |= random.choice(ALLOWED_TAGGED_CE) << 49
        if (data & 0xffffffff) < decode_cap_base(data):
            tag = 0
    return (tag << 64) | data


def generate_addata(elf_path):
    """Generate or remove the sibling .addata file for one ELF."""
    info = read_addata_info(elf_path)
    out_path = elf_path.with_suffix(".addata")
    if info is None:
        out_path.unlink(missing_ok=True)
        return False

    offset, size = info
    with out_path.open("w", encoding="ascii") as output:
        for index in range(size):
            output.write(
                "0x{:08x}:0x{:017x}\n".format(
                    offset + index * 8, random_addata_value()
                )
            )
    return True


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--elf-dir",
        default="two_phase_output/elfs",
        help="Phase-1 ELF directory. Default: two_phase_output/elfs",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    elf_dir = Path(args.elf_dir).resolve()
    elf_files = sorted(elf_dir.glob("*.elf"))
    if not elf_files:
        print("ERROR: no ELF files found in {}".format(elf_dir), file=sys.stderr)
        return 1

    generated = 0
    try:
        for elf_path in elf_files:
            generated += generate_addata(elf_path)
    except Exception as error:
        print("ERROR: {}".format(error), file=sys.stderr)
        return 1

    print("Generated {} .addata file(s) from {} ELF(s).".format(
        generated, len(elf_files)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
