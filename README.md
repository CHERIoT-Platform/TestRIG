# CHERIoT TestRIG — two-phase execution

Two-phase randomised testing for the CHERIoT Sail model:

1. **Generate** random RV32 instruction streams.
2. **Phase 1** — run each stream through Sail once; Sail dumps its
   final memory state to an ELF.
3. **Phase 2** — re-execute each ELF in Sail and emit a per-instruction
   RVFI text trace.

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
head two_phase_output/results/trace_001_sail.rvfi
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
│   ├── trace_001.hex.txt     # random RV32 hex — input to Sail -f
│   └── trace_001.S           # assembly view (human-readable only)
├── elfs/
│   └── trace_001.elf         # phase-1 memory dump
├── results/
│   └── trace_001_sail.rvfi   # phase-2 RVFI text trace (the deliverable)
└── SUMMARY.txt
```

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
  -s, --seed N           RNG seed for reproducibility
      --clean            wipe work-dir contents first
  -h, --help             show this help
```

---

## Layout

```
.
├── Dockerfile                          # runtime-only image (ubuntu:22.04 + libgmp10 + python3)
├── docker-compose.yml                  # testrig, testrig-{quicktest,fulltest,sail-only,custom}
├── run_two_phase.sh                    # one-shot driver
├── utils/scripts/
│   ├── batch_generate_instructions.py  # hex-encoded RV32 generator
│   ├── generate_elfs_from_traces.py    # phase 1
│   ├── run_two_phase_execution.py      # phase 2
│   └── compare_rvfi_text.py            # (optional) text-trace comparator
├── riscv-implementations/
│   └── cheriot-sail/                   # submodule; c_emulator/ has the Sail RVFI binary
├── BUILD_SAIL_MACOS.md                 # native-build instructions for macOS
└── README.orig.md                      # upstream TestRIG README
```
