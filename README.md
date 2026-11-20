# bip377

Rust implementation of draft [BIP-377](https://github.com/bitcoin/bips/pull/2353): the byte encoding of the messages a
coordinator and a signer exchange (Get Info, Get Keys, Register Descriptor,
Address Verification, Signing, Nonce Preparation, Unregister Descriptor). The
format is specified in BIP-377, except the nonce cache (Nonce Preparation and
one-round MuSig2 Signing), which is ahead of the BIP and described in
[NONCE_CACHE.md](NONCE_CACHE.md) until it lands there. The encoding is transport
agnostic, so framing (BBQR) and QR rendering are out of scope.

The codec is imported from bwk.

## Crates

- [`bip377-ll`](bip377-ll/README.md): the codec. `no_std` plus `alloc` with no
  dependency at all, so a bare-metal signer can depend on it directly. Its `ffi`
  feature adds the C binding ([`bip377-ll/include/bip377.h`](bip377-ll/include/bip377.h)).
- `bip377`: re-exports `bip377-ll` as `bip377::ll` and adds `bip377::backend`, the
  conversions between the codec's wire types and those of a `bitcoin` release.

The codec carries keys and paths as raw bytes (`ExtendedKey`, `Fingerprint`,
`PublicKey`, `SecretKey`, `DerivationPath`). The orphan rule rules out `From` impls
between them and the `bitcoin` types, so the backend converts through the
`Backend` trait, implemented by `bip377::backend::Active` for the selected release:

```rust
use bip377::{
    backend::{Active, Backend},
    ll::{Message, decode},
};

let path = Active::to_ll_path(&"m/84'/0'/0'".parse()?);
let xpub = Active::from_ll_xpub(&extended_key)?;

match decode(bytes)? {
    Message::Request(request) => { /* a signer answers it */ }
    Message::Response(response) => { /* a coordinator consumes it */ }
}
```

Converting to the wire only fails for an uncompressed public key; converting from
the wire fails on bytes that are not a valid key.
`bip377::bitcoin` re-exports the `bitcoin` release the backend is built on. `bip377`
is `no_std` and depends on it without default features, so `std` comes from the
caller's own `bitcoin` dependency.

## Features

| Feature flag     | Default | Description                                          |
|------------------|---------|------------------------------------------------------|
| `bitcoin_0_32`   | -       | Convert to and from `bitcoin` 0.32 (0.32.0 or later) |
| `bitcoin_latest` | yes     | Alias for `bitcoin_0_32`                             |

Without a backend feature (`default-features = false`), `bip377` is only the
`bip377::ll` re-export. A new `bitcoin` major release gets its own feature.

[`examples/`](examples) holds one downstream crate pinned at `bitcoin` 0.32.0, the
oldest supported release, and one at 0.32.5, the release Liana builds with. Both
run [`examples/shared/roundtrip.rs`](examples/shared/roundtrip.rs), which converts
their own `bitcoin` types through the backend, encodes, decodes and converts back,
so each only compiles when the backend is that same release.

## Test vectors

[`test_vectors/`](test_vectors) holds the machine-checkable vectors of the
specification, one JSON file per operation (see the Test Vectors section of
[BIP-377](https://github.com/bitcoin/bips/pull/2353) for their format). `nonce_cache.json` and the nonce entries of `invalid.json`
are ahead of the BIP (see [NONCE_CACHE.md](NONCE_CACHE.md)).
`bip377-ll/tests/vectors.rs` checks every one of them.

## Development

```sh
just ci          # lint, tests and release builds, as the CI runs them
just fuzz 60     # every fuzz target for 60 seconds each (nightly + cargo-fuzz)
```

The fuzz targets live in [`fuzz/`](fuzz): `decode` feeds arbitrary bytes to the
decoder, which must never panic, `roundtrip` checks that a decoded message
encodes back to bytes that decode to the same message, `encode` builds messages
from the fuzz bytes and checks that whatever encodes decodes back to the same
message, and `ffi_decode` decodes through the C binding, reads the whole result
back and frees it. `just fuzz` first seeds every corpus with the test vectors
(`fuzz/seed.sh`).

MSRV: 1.88.

## License

MIT, see [LICENSE](LICENSE). The specification text in NONCE_CACHE.md is BSD-2-Clause.
