# Gate toolchain (tools/container.sh): Rust 1.93.1 by digest, rustfmt and clippy from the same
# channel manifest (rustup checks their hashes), cargo-fuzz and cargo-deny built from crates.io with
# their own Cargo.lock (--locked, checksums verified by cargo).
FROM rust:1.93.1-trixie@sha256:ecbe59a8408895edd02d9ef422504b8501dd9fa1526de27a45b73406d734d659
RUN rustup component add rustfmt clippy \
 && cargo install --locked --root /usr/local cargo-fuzz@0.13.2 cargo-deny@0.20.2 \
 && rm -rf /usr/local/cargo/registry /usr/local/cargo/git
