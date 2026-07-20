# syntax=docker/dockerfile:1

# ==============================================================================
# Stage 1: build dei programmi eBPF (richiede nightly + target bpfel-unknown-none)
# ==============================================================================
FROM rust:1.79-bookworm AS ebpf-builder

RUN rustup toolchain install nightly --component rust-src \
    && rustup target add bpfel-unknown-none --toolchain nightly

RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf-dev \
    clang \
    llvm \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/kerneltrace-common ./crates/kerneltrace-common
COPY crates/kerneltrace-ebpf ./crates/kerneltrace-ebpf

RUN cd crates/kerneltrace-ebpf && \
    cargo +nightly build -Z build-std=core --release --target bpfel-unknown-none

# ==============================================================================
# Stage 2: build dell'agente e della CLI (toolchain stable)
# ==============================================================================
FROM rust:1.79-bookworm AS agent-builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

# Il binario eBPF compilato nello stage precedente viene incluso staticamente
# nell'agente tramite include_bytes! (vedi loader/attacher.rs); copiamo
# l'artefatto nella posizione attesa da OUT_DIR prima della build finale.
COPY --from=ebpf-builder /build/target/bpfel-unknown-none/release/kerneltrace-ebpf \
    /build/crates/kerneltrace-ebpf/target/bpfel-unknown-none/release/kerneltrace-ebpf

RUN cargo build --release -p kerneltrace-agent -p kerneltrace-cli

# ==============================================================================
# Stage 3: immagine finale minimale
# ==============================================================================
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libelf1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=agent-builder /build/target/release/kerneltrace-agent /usr/local/bin/
COPY --from=agent-builder /build/target/release/kerneltrace-cli /usr/local/bin/
COPY config/kerneltrace.example.yaml /etc/kerneltrace/kerneltrace.yaml

RUN mkdir -p /var/log/kerneltrace

# L'immagine richiede comunque privilegi elevati a runtime (--privileged
# o le capability equivalenti) indipendentemente dall'utente dichiarato
# qui: la necessità di CAP_BPF/CAP_SYS_ADMIN è intrinseca al caricamento
# di programmi eBPF, non eliminabile lato immagine Docker.
ENTRYPOINT ["/usr/local/bin/kerneltrace-cli"]
CMD ["start", "--config", "/etc/kerneltrace/kerneltrace.yaml"]