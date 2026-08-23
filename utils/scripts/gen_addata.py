#!/usr/bin/env python3
"""Generate Phase-2 additional data from Phase-1 ELF metadata."""

import argparse
import random
import struct
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile


ADDATA_SECTION = ".addata_info"
ADDATA_MAIN_SECTION = ".addata_main"
ADDATA_TAGS_SECTION = ".addata_tags"
# IT8 decodes nonzero cE with XOR 0x1f; encoded values for exponents
# 0x19 through 0x1e are therefore forbidden.
FORBIDDEN_TAGGED_CE = frozenset(
    exponent ^ 0x1f for exponent in range(0x19, 0x1f)
)
ALLOWED_TAGGED_CE = tuple(
    value for value in range(0x20) if value not in FORBIDDEN_TAGGED_CE
)
CAP_BASE_MASK = (1 << 33) - 1
ADDRESS_SPACE_SIZE = 1 << 32


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
    if size == 0:
        raise ValueError("additional-data entry count is zero")
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


def random_addata_address(starting_offset, size_in_bytes):
    """Choose an address inside the additional-data region 75% of the time."""
    region_end = starting_offset + size_in_bytes
    if (size_in_bytes <= 0 or starting_offset < 0 or
            region_end > ADDRESS_SPACE_SIZE):
        raise ValueError("invalid additional-data address region")

    if random.getrandbits(2) != 0:
        return random.randrange(starting_offset, region_end)

    # The remaining 25% is unrestricted and may occasionally land inside.
    return random.getrandbits(32)


def random_addata_value(starting_offset, size_in_bytes):
    """Generate one 65-bit value, constraining tagged values to IT8."""
    tag = random.getrandbits(1)
    data = random.getrandbits(64)
    address = random_addata_address(starting_offset, size_in_bytes)
    data = (data & ~0xffffffff) | address
    if tag:
        data &= ~(1 << 63)
        data &= ~(0x7 << 54)
        data |= random.randrange(6) << 54
        data &= ~(0x1f << 49)
        data |= random.choice(ALLOWED_TAGGED_CE) << 49
        if (data & 0xffffffff) < decode_cap_base(data):
            tag = 0
    return (tag << 64) | data


def encode_addata_main(values):
    """Encode the 64-bit data portion of each entry as little endian."""
    return b"".join(
        (value & 0xffffffffffffffff).to_bytes(8, byteorder="little")
        for value in values
    )


def encode_addata_tags(values):
    """Encode each out-of-band tag as one byte containing zero or one."""
    return bytes((value >> 64) & 1 for value in values)


def embed_addata(elf_path, offset, values):
    """Add or replace the non-loadable data and tag ELF sections."""
    try:
        import lief
    except ImportError as error:
        raise RuntimeError(
            "LIEF is required to embed additional data; install it with "
            "'python3 -m pip install lief'"
        ) from error

    elf = lief.parse(str(elf_path))
    if elf is None:
        raise ValueError("cannot parse ELF file {}".format(elf_path))

    main_data = encode_addata_main(values)
    tag_data = encode_addata_tags(values)
    info_data = struct.pack("<II", offset, len(values))

    for section_name in (ADDATA_SECTION, ADDATA_MAIN_SECTION,
                         ADDATA_TAGS_SECTION):
        old_section = elf.get_section(section_name)
        if old_section is not None:
            elf.remove(old_section)

    for section_name, section_data in (
            (ADDATA_SECTION, info_data),
            (ADDATA_MAIN_SECTION, main_data),
            (ADDATA_TAGS_SECTION, tag_data)):
        section = lief.ELF.Section(section_name)
        section.content = list(section_data)
        added_section = elf.add(section, loaded=False)
        if added_section is None:
            raise RuntimeError("cannot add {} to {}".format(
                section_name, elf_path))
        # Update the section owned by the Binary as well.  Some LIEF versions
        # return a distinct object from Binary.add().
        added_section.content = list(section_data)

    temporary = elf_path.with_name(elf_path.name + ".tmp")
    try:
        elf.write(str(temporary))
        with temporary.open("rb") as embedded_file:
            embedded_elf = ELFFile(embedded_file)
            for section_name, expected_data in (
                    (ADDATA_SECTION, info_data),
                    (ADDATA_MAIN_SECTION, main_data),
                    (ADDATA_TAGS_SECTION, tag_data)):
                embedded_section = embedded_elf.get_section_by_name(
                    section_name)
                actual_data = (embedded_section.data()
                               if embedded_section is not None else None)
                if actual_data != expected_data:
                    actual_size = (len(actual_data)
                                   if actual_data is not None else "missing")
                    raise RuntimeError(
                        "{} in {} has size {}; expected {}".format(
                            section_name, elf_path, actual_size,
                            len(expected_data)))
        temporary.replace(elf_path)
    finally:
        temporary.unlink(missing_ok=True)


def generate_addata(elf_path):
    """Generate and embed additional data for one ELF."""
    info = read_addata_info(elf_path)
    # Remove sidecar files left by the former flow.
    elf_path.with_suffix(".addata").unlink(missing_ok=True)
    if info is None:
        return False

    offset, size = info
    print("Embedding {} entries at 0x{:08x} in {}".format(
        size, offset, elf_path.name))
    size_in_bytes = size * 8
    values = [random_addata_value(offset, size_in_bytes)
              for _ in range(size)]
    embed_addata(elf_path, offset, values)
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

    print("Embedded additional data in {} of {} ELF(s).".format(
        generated, len(elf_files)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
