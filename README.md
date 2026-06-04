# CHERIoT TestRIG — two-phase execution

Two-phase randomised testing for the CHERIoT Sail model:

1. **Generate** random RV32 instruction streams (RV32I + CHERIoT Xcheri).
2. **Phase 1** — run each stream through Sail once; Sail dumps its
   final memory state to an ELF *and* emits a binary RVFI v1 trace
   (`--rvfi-output`). The binary trace is then decoded into a verbose
   labeled text trace (`results/trace_NNN.rvfi`) — this is the primary
   deliverable.
3. **Phase 2** — re-execute each ELF in Sail with all trace channels on
   (`-v` = instr/reg/mem/rvfi/platform/exception) and capture the full
   Sail log as `results/trace_NNN_sail.log`.

Inputs, intermediates, and outputs all land in `./two_phase_output/`.

> Original upstream README is preserved as
> [`README.orig.md`](./README.orig.md).
> RVFI-DII protocol notes are in [`RVFI-DII.md`](./RVFI-DII.md).

---

## Run with Docker (recommended)

Requires Docker Desktop (Mac/Windows) or Docker Engine (Linux). The
image installs only runtime libraries — no Sail rebuild, no OCaml,
no Cabal. Build is ~60 seconds.

```bash
# 1. Build the image (once).
docker compose build

# 2. Run. Pick one:
docker compose up testrig-quicktest     # 10 traces (≈1 min)
docker compose up testrig-fulltest      # 100 traces (≈10 min)
docker compose up testrig-sail-only     # 50 traces

# 3. Inspect results — written to ./two_phase_output on the host.
ls two_phase_output/
cat two_phase_output/SUMMARY.txt
head -40 two_phase_output/results/trace_001.rvfi      # labeled RVFI text
head -20 two_phase_output/results/trace_001_sail.log  # Phase-2 Sail log
```

Interactive container for ad-hoc runs:

```bash
docker compose run --rm testrig                         # drops you to a shell
docker compose run --rm testrig ./run_two_phase.sh -c 5 -n 30 --clean
```

### What you get in `two_phase_output/`

```
two_phase_output/
├── traces/
│   ├── trace_001.hex.txt      # random RV32 hex — input to Sail -f
│   └── trace_001.S            # assembly view (human-readable only)
├── elfs/
│   └── trace_001.elf          # phase-1 memory dump
├── rvfi_bin/
│   └── trace_001.rvfi.bin     # phase-1 binary RVFI v1 trace (88 B/insn)
├── results/
│   ├── trace_001.rvfi         # phase-1 labeled RVFI text (the deliverable)
│   └── trace_001_sail.log     # phase-2 full Sail log (-v all channels)
└── SUMMARY.txt
```

### What the RVFI text trace looks like

Each instruction becomes one block with every v1 RVFI field on its own
line, plus a best-effort mnemonic hint:

```
# --- RVFI packet 7 ---
order     : 7
halt      : 0x00
trap      : 0x00
intr      : 0x00
pc_rdata  : 0x000000008000001c
pc_wdata  : 0x0000000080000020
insn      : 0x00700293  ; addi x5, x0, 7
rs1       : x00  rdata=0x0000000000000000
rs2       : x00  rdata=0x0000000000000000
rd        : x05  wdata=0x0000000000000007
mem_addr  : 0x0000000000000000
mem_rmask : 0b00000000 (0 byte(s))
mem_rdata : 0x0000000000000000
mem_wmask : 0b00000000 (0 byte(s))
mem_wdata : 0x0000000000000000
```

The trace ends with a single halt packet (`halt = 0x01`), mirroring
QCVEngine's on-wire format. v1 packets do **not** carry CHERI cap
register data (`cs1_rdata`/`cs2_rdata`/`cd_wdata`/tags) — the Sail
binary is hard-coded to v1 (`riscv_sim.c:75`). Promoting to v2 requires
a Sail-side source change; ping if you want that follow-up.

### Prebuilt Sail binary

The repo ships a prebuilt Linux x86_64 `cheri_riscv_rvfi_RV32` at
`riscv-implementations/cheriot-sail/c_emulator/`. That's what the
Docker image uses — no rebuild needed. If the binary has been wiped
(see `BUILD_SAIL_MACOS.md`) and you want native macOS execution
instead of Docker, rebuild from source.

---

## Run without Docker (Linux)

```bash
sudo apt-get install -y libgmp10 python3
./run_two_phase.sh --count 10 --instructions 50 --clean
```

The prebuilt binary needs `libgmp.so.10`, `libstdc++.so.6`, and a
2022-era glibc. On other distros, install the equivalents.

For a native build (required on macOS, or if you want to modify
Sail), see [`BUILD_SAIL_MACOS.md`](./BUILD_SAIL_MACOS.md).

---

## `run_two_phase.sh` options

```
  -c, --count N          number of random traces          (default: 10)
  -n, --instructions N   instructions per trace           (default: 50)
  -a, --architecture A   arch string (drives register range) (default:
                                       rv32ecZifencei_Xcheriot)
  -w, --work-dir DIR     output directory                  (default:
                                       ./two_phase_output)
  -s, --seed N           RNG seed (Python fallback only; QCVEngine ignores)
      --gen MODE         generator: auto | qcvengine | python (default: auto)
      --template LABEL   QCVEngine template to use        (default: random)
      --clean            wipe work-dir contents first
  -h, --help             show this help
```

### What's in the generated streams

By default the driver uses the **QCVEngine** Haskell generator — the same
one used by the upstream CHERIoT verification engine. It's built into the
Docker image automatically (`hs-builder` stage), installed on `PATH` as
`qcvengine-gen`, and invoked via its `--output-dir` mode, which bypasses
sockets and writes hex instruction files directly (no RVFI-DII
round-tripping required). On hosts without Docker, build it locally:

```bash
(cd vengines/QuickCheckVEngine && cabal v2-build exe:QCVEngine)
```

Templates live in `vengines/QuickCheckVEngine/src/QuickCheckVEngine/Templates/`;
pick one with `--template LABEL`. A few useful labels:

- `random` (default) — balanced mix of arith / mem / control / CHERI
- `caprandom` — CHERI-heavy random template
- `arith`, `mem`, `control`, `capinspect`, `caparith`, `capmisc`, …

The full list is printed by `QCVEngine` when given an unknown label, or
see `allTests` in `Main.hs`.

### Python fallback generator

A pure-Python port lives at `utils/scripts/batch_generate_instructions.py`.
It's used automatically when `qcvengine-gen` is not on `PATH`, or can be
forced with `--gen python`. Encodings are ported directly from the
QuickCheckVEngine Haskell source
(`vengines/QuickCheckVEngine/src/RISCV/RV32_Xcheri.hs`), so the bit layouts
match what the Haskell generator would produce. Current CHERIoT coverage:

- **Inspection:** cgetperm, cgettype, cgetbase, cgetlen, cgettag,
  cgetaddr, cgethigh, cgettop, cmove, ccleartag
- **Arithmetic / modification:** csub, cincaddr, cincaddrimm, csetaddr,
  csethigh, csetbounds, csetboundsexact, csetboundsimm, candperm
- **Assertions:** ctestsubset, csetequalexact

Mix is ~50/50 by default. Tune with:

```bash
# CHERI-heavy Python fallback (90% cap instructions)
docker compose run --rm testrig python3 utils/scripts/batch_generate_instructions.py \
    -o /testrig/two_phase_output/traces -c 10 -n 50 --cheri-weight 0.9
# Force the Python fallback through the normal driver
./run_two_phase.sh --gen python -c 5 -n 30 --clean
# Force QCVEngine even if both are available
./run_two_phase.sh --gen qcvengine --template caprandom -c 5 -n 30 --clean
```

---

## Layout

```
.
├── Dockerfile                          # runtime-only image (ubuntu:22.04 + libgmp10 + python3)
├── docker-compose.yml                  # testrig, testrig-{quicktest,fulltest,sail-only,custom}
├── run_two_phase.sh                    # one-shot driver
├── utils/scripts/
│   ├── batch_generate_instructions.py  # hex-encoded RV32 + Xcheri generator
│   ├── generate_elfs_from_traces.py    # phase 1 (ELF + binary RVFI)
│   ├── rvfi_to_text.py                 # RVFI v1 binary → verbose labeled text
│   ├── run_two_phase_execution.py      # phase 2 (full Sail log)
│   └── compare_rvfi_text.py            # (optional) text-trace comparator
├── riscv-implementations/
│   └── cheriot-sail/                   # submodule; c_emulator/ has the Sail RVFI binary
├── vengines/QuickCheckVEngine/         # authoritative CHERIoT instr encodings (Haskell, source of truth)
├── BUILD_SAIL_MACOS.md                 # native-build instructions for macOS
└── README.orig.md                      # upstream TestRIG README
```
