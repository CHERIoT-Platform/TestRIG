# Multi-stage Dockerfile for CHERIoT TestRIG two-phase execution.
#
# Stage 1 (sail-builder):  install opam + sail + ELFIO + C++ toolchain,
#                          then build cheri_riscv_rvfi_RV32 from the
#                          cheriot-sail submodule.
# Stage 2 (hs-builder):    GHC + cabal on top of ubuntu:22.04; build
#                          QCVEngine to produce a Haskell generator that
#                          can emit hex instruction files to disk
#                          (--output-dir mode), eliminating the socket
#                          dependency on the testrig path.
# Stage 3 (runtime):       small ubuntu:22.04 image with the Sail binary,
#                          the QCVEngine binary, python3, and libgmp10.
#
# Why not use the prebuilt binary from the host? macOS users rebuild
# locally for native speed, which leaves a Mach-O binary at the expected
# path — unusable from a Linux container. Building inside the image makes
# `docker compose up` work on every host OS.
#
# Branch / submodule policy is NOT enforced inside this Dockerfile —
# run `./scripts/setup_submodules.sh` on the host before building so
# the working tree is at the right tips:
#   TestRIG / cheriot-sail   →  dii-read-from-file
#   cheriot-sail/sail-riscv  →  cheriot-dii-read-from-file
# The wrapper `./scripts/docker_build.sh` does both steps in one go.

# ---------------------------------------------------------------------------
# Stage 1 — build Sail RVFI simulator from source
# ---------------------------------------------------------------------------
FROM ubuntu:22.04 AS sail-builder

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
# Stage 2 — build QCVEngine (Haskell instruction generator)
# ---------------------------------------------------------------------------
# GHC + cabal are kept out of the runtime image (they add ~700 MB). The
# cabal build produces a single statically-linkable-ish executable that
# only depends on libgmp10 + libstdc++6 at runtime (both already installed
# for Sail). --output-dir mode on QCVEngine replaces the old socket +
# Python-generator path with a plain file-writing batch generator.
FROM ubuntu:22.04 AS hs-builder

ENV DEBIAN_FRONTEND=noninteractive TZ=UTC

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git \
        ghc cabal-install \
        libgmp-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# Only the QCVEngine tree is needed (cabal.project lives alongside it).
COPY vengines/QuickCheckVEngine /src/QCVEngine

# Defence in depth: even if .dockerignore is bypassed and the host's
# dist-newstyle/ tree slips into the COPY, wipe it so cabal v2-build
# re-links against the Main.hs inside the image rather than reusing a
# pre-built binary that predates our --output-dir patch.
RUN cd /src/QCVEngine \
 && rm -rf dist-newstyle dist .stack-work bin \
 && cabal update \
 && cabal v2-build --ghc-options=-O exe:QCVEngine \
 && mkdir -p /out \
 && bin=$(find /src/QCVEngine/dist-newstyle -type f -name QCVEngine -executable | head -n1) \
 && test -n "${bin}" \
 && cp "${bin}" /out/QCVEngine \
 && test -x /out/QCVEngine

# ---------------------------------------------------------------------------
# Stage 3 — runtime image
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
COPY --from=sail-builder /src/cheriot-sail/c_emulator/cheri_riscv_rvfi_RV32 \
     /testrig/riscv-implementations/cheriot-sail/c_emulator/cheri_riscv_rvfi_RV32

# Drop in the QCVEngine generator binary (replaces Python generator in
# run_two_phase.sh). Exposed on PATH as 'qcvengine-gen' for convenience.
COPY --from=hs-builder /out/QCVEngine /usr/local/bin/qcvengine-gen

RUN chmod +x /testrig/run_two_phase.sh /testrig/utils/scripts/*.py \
 && /testrig/riscv-implementations/cheriot-sail/c_emulator/cheri_riscv_rvfi_RV32 --help >/dev/null \
 && test -x /usr/local/bin/qcvengine-gen

ENV TESTRIG_ROOT=/testrig

CMD ["./run_two_phase.sh", "--help"]
