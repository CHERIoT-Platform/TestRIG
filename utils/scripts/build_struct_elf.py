#!/usr/bin/env python3
"""Build executable structured ELFs from QCVEngine strrandom traces.

The input is the annotated hexadecimal text emitted by QCVEngine.  This tool
lays instructions out densely from 0x80000080, retargets structured branches,
connects subroutine call sites into a rooted forest, replaces unused call sites
with width-preserving NOPs, and writes an ELF32 RISC-V executable with symbols.
The ELF also contains the CHERIoT exception handler used by Sail at 0x807f0000.
"""

import argparse
import glob
import os
import random
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_BASE = 0x80000080
EXCEPTION_HANDLER_ADDRESS = 0x807F0000
EXCEPTION_HANDLER_INSTRUCTIONS = (
    0x03C007DB,  # cspecialr ca5, mtcc
    0x03F0075B,  # cspecialr ca4, mepcc
    0x20E787DB,  # csetaddr ca5, ca5, a4
    0x004797DB,  # cincoffset ca5, ca5, 4
    0x03F7805B,  # cspecialw mepcc, ca5
    0x30200073,  # mret
)
MAIN_JAL = 0x000000EF
STACK_PUSH = 0x00113023
STACK_ADJUST_DOWN = 0xFF81115B
STACK_ADJUST_UP = 0x0081115B
STACK_POP = 0x00013083
RETURN_JALR = 0x00008067
RETURN_CJR = 0x00008082
MCYCLE_CSR = 0xB00
NOP32 = 0x00000013
NOP16 = 0x0001

TRACE_RE = re.compile(r"^\s*(?:0x)?([0-9a-fA-F]{1,8})(?:\s*(?:#.*)?)?$")


class TraceError(ValueError):
    """An input trace does not have the required structured shape."""


@dataclass
class Instruction:
    value: int
    line_number: int
    comment: str = ""
    address: int = 0

    @property
    def size(self):
        return 4 if self.value & 0x3 == 0x3 else 2


@dataclass
class BranchSequence:
    start: int
    branch: int
    target: int = -1


@dataclass
class Subroutine:
    index: int
    start: int
    end: int
    body_start: int
    body_end: int
    calls: list = field(default_factory=list)
    branches: list = field(default_factory=list)


@dataclass
class CallEdge:
    parent: int
    child: int
    instruction: int


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input-dir", default="two_phase_output/traces",
        help="directory containing structured trace text files",
    )
    parser.add_argument(
        "--output-dir", default="two_phase_output/struct_elfs",
        help="directory for generated ELF files",
    )
    parser.add_argument(
        "--input-pattern", default="*.txt",
        help="input glob relative to --input-dir (default: *.txt)",
    )
    parser.add_argument(
        "--base-address", type=lambda value: int(value, 0),
        default=DEFAULT_BASE,
        help="ELF entry and code base address (default: 0x80000080)",
    )
    parser.add_argument("--seed", type=int, help="reproducible random seed")
    parser.add_argument(
        "--call-tree", nargs="?", const="auto", metavar="DIR",
        help="write one Graphviz .dot call-tree diagram per trace; optionally "
             "select its output directory",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args(argv)


def trace_stem(path):
    name = Path(path).name
    for suffix in (".hex.txt", ".txt", ".hex"):
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return Path(name).stem


def read_trace(path):
    instructions = []
    with open(path, "r", encoding="utf-8", errors="replace") as stream:
        for line_number, raw_line in enumerate(stream, 1):
            code, _, comment = raw_line.partition("#")
            code = code.strip()
            if not code:
                continue
            match = TRACE_RE.match(raw_line.rstrip("\n"))
            if match is None:
                raise TraceError(
                    "{}:{}: expected one hexadecimal instruction".format(
                        path, line_number
                    )
                )
            value = int(match.group(1), 16)
            instructions.append(Instruction(value, line_number, comment.strip()))
    if not instructions:
        raise TraceError("{}: trace contains no instructions".format(path))
    return instructions


def assign_addresses(instructions, base_address):
    address = base_address
    for instruction in instructions:
        instruction.address = address
        address += instruction.size
    return address


def find_main_loop(instructions):
    for index in range(len(instructions) - 2):
        if all(instructions[index + offset].value == MAIN_JAL
               for offset in range(3)):
            return index
    raise TraceError("missing three consecutive 'jal x1, 0' main instructions")


def is_jal_call(instruction):
    return (instruction.size == 4 and instruction.value & 0x7F == 0x6F
            and (instruction.value >> 7) & 0x1F == 1)


def is_cjal_call(instruction):
    return (instruction.size == 2 and instruction.value & 0x3 == 0x1
            and (instruction.value >> 13) & 0x7 == 0x1)


def is_branch(instruction):
    return instruction.size == 4 and instruction.value & 0x7F == 0x63


def mcycle_read_destination(instruction):
    """Return rd for `csrr rd, mcycle`, or None for another instruction."""
    value = instruction.value
    if (instruction.size == 4
            and value & 0x7F == 0x73
            and (value >> 12) & 0x7 == 0x2
            and (value >> 15) & 0x1F == 0
            and (value >> 20) & 0xFFF == MCYCLE_CSR):
        return (value >> 7) & 0x1F
    return None


def is_branch_sequence_start(instructions, index):
    """Recognize `csrr tmp1, mcycle; andi tmp1, tmp1, mask`."""
    if index + 1 >= len(instructions):
        return False
    destination = mcycle_read_destination(instructions[index])
    if destination is None:
        return False
    andi_value = instructions[index + 1].value
    return (instructions[index + 1].size == 4
            and andi_value & 0x7F == 0x13
            and (andi_value >> 12) & 0x7 == 0x7
            and (andi_value >> 7) & 0x1F == destination
            and (andi_value >> 15) & 0x1F == destination)


def cspecialr_mtdc_destination(instruction):
    """Return cd for `cspecialr cd, mtdc`, or None for another instruction."""
    value = instruction.value
    if (instruction.size == 4
            and value & 0x7F == 0x5B
            and (value >> 25) & 0x7F == 0x01
            and (value >> 20) & 0x1F == 29
            and (value >> 15) & 0x1F == 0
            and (value >> 12) & 0x7 == 0):
        return (value >> 7) & 0x1F
    return None


def is_load_store_with_base(instruction, base_register):
    """Recognize an uncompressed RV32/CHERIoT load or store using rs1."""
    value = instruction.value
    return (instruction.size == 4
            and value & 0x7F in (0x03, 0x23)
            and (value >> 15) & 0x1F == base_register)


def legal_load_store_sequences(instructions, subroutine):
    """Find generated cspecialr/setup/load-store sequences in a body.

    The generator emits zero to two setup instructions after cspecialr, then
    one to three memory operations.  Only the cspecialr may be targeted by a
    rewritten structured branch.
    """
    sequences = []
    for start in range(subroutine.body_start, subroutine.body_end):
        base_register = cspecialr_mtdc_destination(instructions[start])
        if base_register is None or base_register == 0:
            continue

        for setup_count in range(3):
            first_memory = start + 1 + setup_count
            if first_memory >= subroutine.body_end:
                break
            if not is_load_store_with_base(
                    instructions[first_memory], base_register):
                continue

            end = first_memory + 1
            while (end < subroutine.body_end
                   and end - first_memory < 3
                   and is_load_store_with_base(
                       instructions[end], base_register)):
                end += 1
            sequences.append((start, end))
            break
    return sequences


def find_subroutines(instructions, main_loop_index):
    subroutines = []
    cursor = main_loop_index + 3
    while cursor < len(instructions):
        if instructions[cursor].value != STACK_PUSH:
            raise TraceError(
                "line {}: expected subroutine stack push, found 0x{:08x}".format(
                    instructions[cursor].line_number, instructions[cursor].value
                )
            )
        if cursor + 1 >= len(instructions) or \
                instructions[cursor + 1].value != STACK_ADJUST_DOWN:
            raise TraceError(
                "line {}: stack push is not followed by stack adjustment".format(
                    instructions[cursor].line_number
                )
            )

        exit_index = None
        for candidate in range(cursor + 2, len(instructions) - 2):
            if (instructions[candidate].value == STACK_ADJUST_UP
                    and instructions[candidate + 1].value == STACK_POP
                    and instructions[candidate + 2].value
                    in (RETURN_JALR, RETURN_CJR)):
                exit_index = candidate
                break
        if exit_index is None:
            raise TraceError(
                "line {}: subroutine has no stack-pop/return sequence".format(
                    instructions[cursor].line_number
                )
            )

        subroutine = Subroutine(
            index=len(subroutines),
            start=cursor,
            end=exit_index + 3,
            body_start=cursor + 2,
            body_end=exit_index,
        )
        subroutine.calls = [
            index for index in range(subroutine.body_start, subroutine.body_end)
            if is_jal_call(instructions[index]) or is_cjal_call(instructions[index])
        ]
        subroutine.branches = find_branch_sequences(instructions, subroutine)
        subroutines.append(subroutine)
        cursor = subroutine.end

    if not subroutines:
        raise TraceError("trace contains no structured subroutines")
    return subroutines


def find_branch_sequences(instructions, subroutine):
    sequences = []
    index = subroutine.body_start
    while index < subroutine.body_end:
        if not is_branch_sequence_start(instructions, index):
            index += 1
            continue
        branch_index = None
        for candidate in range(index + 1, subroutine.body_end):
            if is_branch(instructions[candidate]):
                branch_index = candidate
                break
            if is_branch_sequence_start(instructions, candidate):
                break
        if branch_index is None:
            raise TraceError(
                "line {}: branch sequence has no terminating branch".format(
                    instructions[index].line_number
                )
            )
        sequences.append(BranchSequence(index, branch_index))
        index = branch_index + 1
    return sequences


def signed_range_fits(offset, bits):
    return offset % 2 == 0 and -(1 << (bits - 1)) <= offset < (1 << (bits - 1))


def call_offset_fits(instruction, target_address):
    offset = target_address - instruction.address
    return signed_range_fits(offset, 21 if instruction.size == 4 else 12)


def encode_jal(original, offset):
    if not signed_range_fits(offset, 21):
        raise TraceError("JAL offset {} is out of range".format(offset))
    immediate = offset & 0x1FFFFF
    encoded = original & 0x00000FFF
    encoded |= ((immediate >> 20) & 0x1) << 31
    encoded |= ((immediate >> 1) & 0x3FF) << 21
    encoded |= ((immediate >> 11) & 0x1) << 20
    encoded |= ((immediate >> 12) & 0xFF) << 12
    return encoded


def encode_cjal(original, offset):
    if not signed_range_fits(offset, 12):
        raise TraceError("C.JAL offset {} is out of range".format(offset))
    immediate = offset & 0xFFF
    encoded = original & 0xE003
    encoded |= ((immediate >> 11) & 0x1) << 12
    encoded |= ((immediate >> 4) & 0x1) << 11
    encoded |= ((immediate >> 8) & 0x3) << 9
    encoded |= ((immediate >> 10) & 0x1) << 8
    encoded |= ((immediate >> 6) & 0x1) << 7
    encoded |= ((immediate >> 7) & 0x1) << 6
    encoded |= ((immediate >> 1) & 0x7) << 3
    encoded |= ((immediate >> 5) & 0x1) << 2
    return encoded


def retarget_call(instruction, target_address):
    offset = target_address - instruction.address
    if instruction.size == 4:
        instruction.value = encode_jal(instruction.value, offset)
    else:
        instruction.value = encode_cjal(instruction.value, offset)


def encode_branch(original, offset):
    if not signed_range_fits(offset, 13):
        raise TraceError("branch offset {} is out of range".format(offset))
    immediate = offset & 0x1FFF
    encoded = original & 0x01FFF07F
    encoded |= ((immediate >> 12) & 0x1) << 31
    encoded |= ((immediate >> 5) & 0x3F) << 25
    encoded |= ((immediate >> 1) & 0xF) << 8
    encoded |= ((immediate >> 11) & 0x1) << 7
    return encoded


def assign_branch_targets(instructions, subroutines, rng):
    symbols = []
    for subroutine in subroutines:
        illegal = set()
        for sequence in subroutine.branches:
            illegal.update(range(sequence.start + 1, sequence.branch + 1))
        for sequence_start, sequence_end in legal_load_store_sequences(
                instructions, subroutine):
            illegal.update(range(sequence_start + 1, sequence_end))
        legal = [
            index for index in range(subroutine.body_start, subroutine.body_end)
            if index not in illegal
        ]
        for branch_number, sequence in enumerate(subroutine.branches):
            branch = instructions[sequence.branch]
            candidates = [
                index for index in legal
                if index != sequence.branch
                and signed_range_fits(
                    instructions[index].address - branch.address, 13
                )
            ]
            if not candidates:
                raise TraceError(
                    "line {}: branch has no legal nonzero target".format(
                        branch.line_number
                    )
                )
            old_offset = decode_branch_offset(branch.value)
            same_sign = [
                index for index in candidates
                if ((instructions[index].address - branch.address) > 0)
                == (old_offset > 0)
            ]
            target = rng.choice(same_sign if same_sign else candidates)
            sequence.target = target
            offset = instructions[target].address - branch.address
            branch.value = encode_branch(branch.value, offset)
            symbols.append((
                "subroutine_{:03d}_branch_target_{:03d}".format(
                    subroutine.index, branch_number
                ),
                instructions[target].address,
                0,
                0,
            ))
    return symbols


def decode_branch_offset(value):
    immediate = (((value >> 31) & 0x1) << 12
                 | ((value >> 25) & 0x3F) << 5
                 | ((value >> 8) & 0xF) << 1
                 | ((value >> 7) & 0x1) << 11)
    return immediate - 0x2000 if immediate & 0x1000 else immediate


def build_call_tree(instructions, main_loop_index, subroutines, rng):
    if len(subroutines) < 2:
        raise TraceError("at least two subroutines are required for main roots")

    for _attempt in range(1000):
        roots = rng.sample(range(len(subroutines)), 2)
        unconnected = set(range(len(subroutines))) - set(roots)
        connected = list(roots)
        unused = {
            subroutine.index: list(subroutine.calls)
            for subroutine in subroutines
        }
        edges = []

        while unconnected:
            choices = []
            for parent in connected:
                for call_index in unused[parent]:
                    call = instructions[call_index]
                    for child in unconnected:
                        target = instructions[subroutines[child].start].address
                        if call_offset_fits(call, target):
                            choices.append((parent, child, call_index))
            if not choices:
                break
            parent, child, call_index = rng.choice(choices)
            unused[parent].remove(call_index)
            unconnected.remove(child)
            connected.append(child)
            edges.append(CallEdge(parent, child, call_index))

        if not unconnected:
            break
    else:
        raise TraceError("could not construct a range-valid call tree")

    for root_number, subroutine_index in enumerate(roots):
        root_call = instructions[main_loop_index + root_number]
        target = instructions[subroutines[subroutine_index].start].address
        retarget_call(root_call, target)

    loop_call = instructions[main_loop_index + 2]
    retarget_call(loop_call, instructions[main_loop_index].address)

    used_calls = set()
    for edge in edges:
        call = instructions[edge.instruction]
        target = instructions[subroutines[edge.child].start].address
        retarget_call(call, target)
        used_calls.add(edge.instruction)

    for subroutine in subroutines:
        for call_index in subroutine.calls:
            if call_index not in used_calls:
                call = instructions[call_index]
                call.value = NOP32 if call.size == 4 else NOP16

    return roots, edges


def instruction_bytes(instructions):
    output = bytearray()
    for instruction in instructions:
        if instruction.size == 4:
            output.extend(struct.pack("<I", instruction.value))
        else:
            output.extend(struct.pack("<H", instruction.value & 0xFFFF))
    return bytes(output)


def align(value, alignment):
    return (value + alignment - 1) & -alignment


def make_string_table(strings):
    data = bytearray(b"\0")
    offsets = {"": 0}
    for value in strings:
        if value not in offsets:
            offsets[value] = len(data)
            data.extend(value.encode("ascii") + b"\0")
    return bytes(data), offsets


def write_elf(path, code, base_address, symbols):
    # ELF32 little-endian RISC-V with code and exception-handler PT_LOADs.
    ehsize = 52
    phentsize = 32
    shentsize = 40
    phoff = ehsize
    page_size = 0x1000
    text_offset = page_size + (base_address & (page_size - 1))
    handler = struct.pack(
        "<{}I".format(len(EXCEPTION_HANDLER_INSTRUCTIONS)),
        *EXCEPTION_HANDLER_INSTRUCTIONS
    )
    handler_offset = align(text_offset + len(code), page_size)

    symbols = list(symbols) + [
        ("exception_handler", EXCEPTION_HANDLER_ADDRESS, len(handler), 2)
    ]
    symbol_names = [symbol[0] for symbol in symbols]
    strtab, string_offsets = make_string_table(symbol_names)
    shstrtab, section_offsets = make_string_table(
        [".text", ".exception_handler", ".symtab", ".strtab", ".shstrtab"]
    )

    symtab = bytearray(b"\0" * 16)
    for name, value, size, symbol_type in symbols:
        info = (1 << 4) | symbol_type  # STB_GLOBAL | type
        section_index = 2 if name == "exception_handler" else 1
        symtab.extend(struct.pack(
            "<IIIBBH", string_offsets[name], value, size, info, 0,
            section_index
        ))

    symtab_offset = align(handler_offset + len(handler), 4)
    strtab_offset = symtab_offset + len(symtab)
    shstrtab_offset = strtab_offset + len(strtab)
    shoff = align(shstrtab_offset + len(shstrtab), 4)
    section_count = 6
    file_size = shoff + section_count * shentsize
    image = bytearray(file_size)

    ident = b"\x7fELF" + bytes([1, 1, 1, 0, 0]) + b"\0" * 7
    image[:ehsize] = struct.pack(
        "<16sHHIIIIIHHHHHH", ident, 2, 243, 1, base_address, phoff,
        shoff, 1, ehsize, phentsize, 2, shentsize, section_count, 5
    )
    image[phoff:phoff + phentsize] = struct.pack(
        "<IIIIIIII", 1, text_offset, base_address, base_address, len(code),
        len(code), 5, page_size
    )
    image[phoff + phentsize:phoff + 2 * phentsize] = struct.pack(
        "<IIIIIIII", 1, handler_offset, EXCEPTION_HANDLER_ADDRESS,
        EXCEPTION_HANDLER_ADDRESS, len(handler), len(handler), 5, page_size
    )
    image[text_offset:text_offset + len(code)] = code
    image[handler_offset:handler_offset + len(handler)] = handler
    image[symtab_offset:symtab_offset + len(symtab)] = symtab
    image[strtab_offset:strtab_offset + len(strtab)] = strtab
    image[shstrtab_offset:shstrtab_offset + len(shstrtab)] = shstrtab

    section_headers = [b"\0" * shentsize]
    section_headers.append(struct.pack(
        "<IIIIIIIIII", section_offsets[".text"], 1, 0x6, base_address,
        text_offset, len(code), 0, 0, 2, 0
    ))
    section_headers.append(struct.pack(
        "<IIIIIIIIII", section_offsets[".exception_handler"], 1, 0x6,
        EXCEPTION_HANDLER_ADDRESS, handler_offset, len(handler), 0, 0, 4, 0
    ))
    section_headers.append(struct.pack(
        "<IIIIIIIIII", section_offsets[".symtab"], 2, 0, 0,
        symtab_offset, len(symtab), 4, 1, 4, 16
    ))
    section_headers.append(struct.pack(
        "<IIIIIIIIII", section_offsets[".strtab"], 3, 0, 0,
        strtab_offset, len(strtab), 0, 0, 1, 0
    ))
    section_headers.append(struct.pack(
        "<IIIIIIIIII", section_offsets[".shstrtab"], 3, 0, 0,
        shstrtab_offset, len(shstrtab), 0, 0, 1, 0
    ))
    image[shoff:shoff + section_count * shentsize] = b"".join(section_headers)

    with open(path, "wb") as stream:
        stream.write(image)


def write_call_tree(path, trace_name, roots, edges):
    lines = [
        "digraph call_tree {",
        "  label=\"{}\";".format(trace_name),
        "  labelloc=t;",
        "  main [shape=box];",
    ]
    for root_number, root in enumerate(roots):
        lines.append("  main -> subroutine_{:03d} [label=\"root {}\"];".format(
            root, root_number + 1
        ))
    for edge in edges:
        lines.append(
            "  subroutine_{:03d} -> subroutine_{:03d};".format(
                edge.parent, edge.child
            )
        )
    lines.append("}")
    with open(path, "w", encoding="ascii") as stream:
        stream.write("\n".join(lines) + "\n")


def process_trace(trace_path, elf_path, dot_path, base_address, rng, verbose):
    instructions = read_trace(trace_path)
    assign_addresses(instructions, base_address)
    main_loop_index = find_main_loop(instructions)
    subroutines = find_subroutines(instructions, main_loop_index)
    branch_symbols = assign_branch_targets(instructions, subroutines, rng)
    roots, edges = build_call_tree(
        instructions, main_loop_index, subroutines, rng
    )

    symbols = [
        ("_start", base_address, 0, 2),
        ("main_call_root_1", instructions[main_loop_index].address, 0, 0),
        ("main_call_root_2", instructions[main_loop_index + 1].address, 0, 0),
        ("main_loop", instructions[main_loop_index + 2].address, 0, 0),
    ]
    for subroutine in subroutines:
        start = instructions[subroutine.start].address
        end = (instructions[subroutine.end - 1].address
               + instructions[subroutine.end - 1].size)
        symbols.append((
            "subroutine_{:03d}".format(subroutine.index),
            start,
            end - start,
            2,
        ))
    symbols.extend(branch_symbols)

    os.makedirs(os.path.dirname(elf_path), exist_ok=True)
    write_elf(
        elf_path, instruction_bytes(instructions), base_address, symbols
    )
    if dot_path:
        os.makedirs(os.path.dirname(dot_path), exist_ok=True)
        write_call_tree(dot_path, trace_stem(trace_path), roots, edges)
    if verbose:
        print("  {}: {} instructions, {} subroutines, {} tree edges".format(
            os.path.basename(trace_path), len(instructions), len(subroutines),
            len(edges)
        ))


def main(argv=None):
    args = parse_args(argv)
    traces = sorted(glob.glob(os.path.join(args.input_dir, args.input_pattern)))
    if not traces:
        print(
            "ERROR: no files matching {} in {}".format(
                args.input_pattern, args.input_dir
            ),
            file=sys.stderr,
        )
        return 1

    os.makedirs(args.output_dir, exist_ok=True)
    dot_dir = None
    if args.call_tree:
        dot_dir = (args.output_dir if args.call_tree == "auto"
                   else args.call_tree)

    master_rng = random.Random(args.seed)
    failures = 0
    for trace_path in traces:
        name = trace_stem(trace_path)
        elf_path = os.path.join(args.output_dir, name + ".elf")
        dot_path = os.path.join(dot_dir, name + "_call_tree.dot") \
            if dot_dir else None
        trace_rng = random.Random(master_rng.getrandbits(64))
        try:
            process_trace(
                trace_path, elf_path, dot_path, args.base_address,
                trace_rng, args.verbose
            )
            print("[OK] {} -> {}".format(trace_path, elf_path))
        except (OSError, TraceError) as error:
            failures += 1
            print("[FAIL] {}: {}".format(trace_path, error), file=sys.stderr)

    print("Processed {} trace(s): {} passed, {} failed".format(
        len(traces), len(traces) - failures, failures
    ))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
