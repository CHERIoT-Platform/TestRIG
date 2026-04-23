# Multi-stage Dockerfile for CHERIoT TestRIG two-phase execution.
#
# Stage 1 (builder):  install opam + sail + ELFIO + C++ toolchain, then
#                     build cheri_riscv_rvfi_RV32 from the cheriot-sail
#                     submodule.
# Stage 2 (runtime):  small ubuntu:22.04 image with only the runtime libs
#                     (libgmp10) + python3 + the compiled binary.
#
# Why not use the prebuilt binary from the host? macOS users rebuild
# locally for native speed, which leaves a Mach-O binary at the expected
# path — unusable from a Linux container. Building inside the image makes
# `docker compose up` work on every host OS.

# ---------------------------------------------------------------------------
# Stage 1 — build Sail RVFI simulator from source
# ---------------------------------------------------------------------------
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive TZ=UTC

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential git curl ca-certificates pkg-config \
        opam z3 \
        libgmp-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Header-only ELFIO (used by mem_dump.cpp).
RUN git clone --depth=1 https://github.com/serge1/ELFIO.git /opt/elfio

# Install Sail via opam (a pinned OCaml switch to keep builds reproducible).
RUN opam init --bare --disable-sandboxing -y \
 && opam switch create cheriot 4.14.1 \
 && opam install -y sail

WORKDIR /src
COPY riscv-implementations/cheriot-sail /src/cheriot-sail

# Build cheri_riscv_rvfi_RV32. opam env is only active for this RUN.
# Scrub any host-built binary/objects first — if the user rebuilt natively on
# macOS, `make` would otherwise see the Mach-O target as up-to-date and skip
# the Linux build, leaving an unusable binary ("Exec format error").
RUN bash -lc '\
    eval $(opam env --switch=cheriot) && \
    cd /src/cheriot-sail && \
    rm -f c_emulator/cheri_riscv_rvfi_RV32 c_emulator/*.o && \
    make ARCH=RV32 ELFIO_DIR=/opt/elfio rvfi && \
    test -x c_emulator/cheri_riscv_rvfi_RV32 && \
    c_emulator/cheri_riscv_rvfi_RV32 --help >/dev/null'

# ---------------------------------------------------------------------------
# Stage 2 — runtime image
# ---------------------------------------------------------------------------
FROM ubuntu:22.04

LABEL description="CHERIoT TestRIG — two-phase execution (runtime)"

ENV DEBIAN_FRONTEND=noninteractive TZ=UTC

RUN apt-get update && apt-get install -y --no-install-recommends \
        libgmp10 libstdc++6 python3 bash file \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /testrig
COPY . /testrig/

# Drop in the freshly-built Linux binary (clobbering any host binary the
# COPY above carried in).
COPY --from=builder /src/cheriot-sail/c_emulator/cheri_riscv_rvfi_RV32 \
     /testrig/riscv-implementations/cheriot-sail/c_emulator/cheri_riscv_rvfi_RV32

RUN chmod +x /testrig/run_two_phase.sh /testrig/utils/scripts/*.py \
 && /testrig/riscv-implementations/cheriot-sail/c_emulator/cheri_riscv_rvfi_RV32 --help >/dev/null

ENV TESTRIG_ROOT=/testrig

CMD ["./run_two_phase.sh", "--help"]
