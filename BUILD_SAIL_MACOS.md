# Building `cheri_riscv_rvfi_RV32` on macOS

The prebuilt x86_64 Linux binary that ships under
`riscv-implementations/cheriot-sail/c_emulator/` will not run on
macOS — you need to build from source. These steps have been
tested on both Apple Silicon and Intel Macs.

## 1. Prerequisites via Homebrew

```bash
brew install gmp z3 opam git cmake pkg-config coreutils
```

Make sure you're on a recent Xcode Command Line Tools release
(`xcode-select --install` if `clang++ --version` reports < 14).

## 2. OCaml + Sail via opam

```bash
opam init --bare --auto-setup --yes
opam switch create cheriot 4.14.1
eval $(opam env --switch=cheriot)
opam install -y sail
```

Verify:

```bash
sail --version
```

## 3. ELFIO (header-only C++ library)

There is **no Homebrew formula** for ELFIO, so clone it somewhere
persistent (e.g. `/opt/elfio` or `$HOME/src/elfio`) and note the
path — you will pass it to `make` via `ELFIO_DIR`.

```bash
git clone https://github.com/serge1/ELFIO.git /opt/elfio
```

`ELFIO_DIR` must point to the directory that **contains** the
`elfio/` subfolder (so the compiler sees `#include <elfio/elfio.hpp>`).
After the clone above, use `ELFIO_DIR=/opt/elfio`.

## 4. Initialise submodules

From the TestRIG repo root (once — not needed if you cloned with
`--recurse-submodules`):

```bash
git submodule update --init --recursive
```

## 5. Build the RVFI simulator

```bash
cd riscv-implementations/cheriot-sail
eval $(opam env --switch=cheriot)

# Point Homebrew's GMP to the compiler. Apple Silicon prefix is
# /opt/homebrew; Intel prefix is /usr/local.
export CPATH="$(brew --prefix gmp)/include:${CPATH}"
export LIBRARY_PATH="$(brew --prefix gmp)/lib:${LIBRARY_PATH}"

# Build — pass ELFIO_DIR explicitly; the default /usr/include does
# NOT exist on macOS.
make ARCH=RV32 ELFIO_DIR=/opt/elfio rvfi
```

Expected output: `c_emulator/cheri_riscv_rvfi_RV32`.

Sanity check:

```bash
./c_emulator/cheri_riscv_rvfi_RV32 --help
```

## 6. Plug it into TestRIG

Nothing special — `run_two_phase.sh` auto-detects the binary at
`riscv-implementations/cheriot-sail/c_emulator/cheri_riscv_rvfi_RV32`,
so once the build succeeds the one-command workflow just works:

```bash
cd /path/to/TestRIG
./run_two_phase.sh --count 10 --instructions 50 --clean
```

## Common issues

- **`fatal error: 'elfio/elfio.hpp' file not found`** — `ELFIO_DIR`
  is wrong. It must point at the directory containing the `elfio/`
  subfolder. After `git clone ... /opt/elfio`, that's `/opt/elfio`.
- **`ld: library not found for -lgmp`** — Homebrew paths aren't
  exported. Re-run the `CPATH` / `LIBRARY_PATH` exports in step 5
  for your shell (Apple Silicon: `/opt/homebrew`, Intel: `/usr/local`).
- **`sail: command not found`** — the opam switch isn't active in
  the current shell. Re-run `eval $(opam env --switch=cheriot)`.
- **`riscv_sim.c: No such file or directory`** — the `sail-riscv`
  submodule is missing. Run
  `git submodule update --init --recursive` at the repo root.
- **Apple Silicon `ld: unknown option: --gc-sections`** — this
  would indicate a Linux-only link flag crept in; the cheriot-sail
  Makefile avoids it, but if a stale checkout still has it, pull
  the latest `dii-read-from-file` branch.

## Alternative: run Linux in Docker on Mac

If you don't need to edit Sail itself, just run TestRIG in Docker —
that uses Linux containers and the prebuilt binary is fine:

```bash
docker compose up testrig-quicktest
```

Docker Desktop on macOS handles the x86_64/arm64 emulation
transparently. Note: emulated x86 is slow; for real work build
Sail natively as described above.
