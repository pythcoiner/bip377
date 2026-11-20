#!/usr/bin/env sh
# Shared by CI and `just ci`.
set -eu
# the codec must build with zero dependencies
cargo build --release -p bip377-ll
cargo build --release -p bip377-ll --features ffi
cargo build --release -p bip377-ll --no-default-features --features coordinator
cargo build --release -p bip377-ll --no-default-features --features signer
cargo build --release -p bip377-ll --no-default-features --features ffi
cargo build --release
cargo build --release --no-default-features --features coordinator
cargo build --release --no-default-features --features signer
cargo build --release --manifest-path examples/bitcoin_0_32_0/Cargo.toml
cargo build --release --manifest-path examples/bitcoin_0_32_5/Cargo.toml
