# bip377

Rust implementation of [BIP-377](https://github.com/bitcoin/bips/pull/2353): the byte encoding of the messages a
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
  `Backend` trait converting the codec's wire types to a consumer's own types with
  `RustBitcoin` its implementation over a `bitcoin` release, and
  `bip377::request` and `bip377::response`, the coordinator's messages over any
  backend's types.

## Coordinator

A coordinator encodes its requests and decodes the answers through a `Backend`.
`bip377::request::Request<B>` and `bip377::response::Response<B>` carry the
messages over the types of backend `B`; with a backend feature, `RustBitcoin`
provides them over `bitcoin` types:

```rust
use bip377::{
    backend::{Backend, rust_bitcoin::RustBitcoin},
    ll::RequestId,
    request::{Body, Request, Sign},
    response::{self, Signed},
};
use bwk_address::backend::rust_bitcoin::Address;

let bytes = RustBitcoin::encode_request(&Request {
    id: RequestId([0, 1]),
    body: Body::Sign(Sign {
        descriptors: vec![],
        psbt, // bitcoin::Psbt
        want_kind: None,
        accept_trimmed: false,
    }),
})?;

match RustBitcoin::decode_response(&answer)?.body {
    response::Body::Signed(Signed::Psbt(psbt)) => { /* a bitcoin::Psbt */ }
    response::Body::Signed(Signed::Signatures(entries)) => { /* ecdsa::Signature, ... */ }
    response::Body::Address(Address::Bitcoin(address)) => {
        /* a bitcoin::Address<NetworkUnchecked> */
    }
    response::Body::Error(error) => { /* the signer refused */ }
    _ => {}
}
```

Keys and Info come back with `bip32::Xpub` and `bip32::Fingerprint`, signatures as
`ecdsa::Signature`, `taproot::Signature`, `XOnlyPublicKey`, `TapLeafHash`,
`PublicKey` and, for a MuSig2 partial signature, `secp256k1::Scalar`, a signed PSBT
as `Psbt`. A BIP-380 descriptor goes out as a
`miniscript::Descriptor<DescriptorPublicKey>` (multipath keys included), written in
its string form with its checksum, and a BIP-388 key as a `request::KeyInfo` (an
optional origin and an `Xpub`). Registration, NoncesPrepared, Unregistered and
Error answers carry no `bitcoin` type and are the codec's own types from
`bip377::ll::response`.

The MuSig2 public nonces, the BIP-374 DLEQ proofs, the BIP-388 policy template and
opaque data (aliases, proofs of registration, nonce session IDs) stay raw. A PSBT
v2 answer fails to convert.

The Address Verification answer is a BIP-321 URI on the wire. `decode_response`
parses it with bwk-address into `bwk_address::backend::rust_bitcoin::Address`:
`Address::Bitcoin` from the URI path, an address of any network, or
`Address::SilentPayment` from the `sp` parameter. A URI it refuses fails with
`rust_bitcoin::Error::AddressUri`.

`rust_bitcoin::Error` covers the whole backend: bytes that do not decode fail with
`Error::Decode`, a request the codec refuses with `Error::Encode`, a value that is
not a valid `bitcoin` type with its own variant (`Error::Psbt`,
`Error::ExtendedKey`, ...). The signer direction (decoding requests, encoding
responses) stays on `bip377::ll`.

A consumer can implement `Backend` over its own types instead, with no bitcoin
feature: it picks the types and writes the conversions to and from the codec's,
and gets the typed messages from `bip377::request` and `bip377::response`
(`tests/mock_backend.rs` is a complete one):

```rust
use bip377::{backend::Backend, ll, request, response};

#[derive(Debug, Clone, PartialEq, Eq)]
enum MyBackend {}

impl Backend for MyBackend {
    type DerivationPath = MyPath;
    type Xpub = MyXpub;
    // ... one type per wire value
    type Request = request::Request<Self>;
    type Response = response::Response<Self>;
    type Error = MyError;

    fn encode_request(request: &request::Request<Self>) -> Result<Vec<u8>, MyError> {
        request::encode(request)
    }

    fn decode_response(bytes: &[u8]) -> Result<response::Response<Self>, MyError> {
        response::decode(bytes)
    }

    fn to_ll_path(path: &MyPath) -> ll::types::DerivationPath { /* ... */ }
    // ... the other to_ll_* and from_ll_* conversions
}
```

`MyError` converts from `ll::encode::Error`, `ll::decode::Error` and
`response::NotAResponse`. `encode_request` and `decode_response` exist with the
`coordinator` feature.

## Backend

The codec carries keys and paths as raw bytes (`ExtendedKey`, `Fingerprint`,
`PublicKey`, `SecretKey`, `DerivationPath`). The orphan rule rules out `From` impls
between them and the `bitcoin` types, so the backend converts through the
`Backend` trait, implemented by `bip377::backend::rust_bitcoin::RustBitcoin` for
the selected release:

```rust
use bip377::backend::{Backend, rust_bitcoin::RustBitcoin};

let path = RustBitcoin::to_ll_path(&"m/84'/0'/0'".parse()?);
let xpub = RustBitcoin::from_ll_xpub(&extended_key)?;
```

Converting to the wire only fails for an uncompressed public key; converting from
the wire fails on bytes that are not a valid key, signature, PSBT or address.
`bip377::bitcoin` re-exports the `bitcoin` release the backend is built on. `bip377`
is `no_std` and depends on it without default features, so `std` comes from the
caller's own `bitcoin` dependency.

## Features

| Feature flag     | Default | Description                                                              |
|------------------|---------|--------------------------------------------------------------------------|
| `coordinator`    | yes     | Encode requests and decode responses                                     |
| `signer`         | yes     | Decode requests and encode responses                                     |
| `bitcoin_0_32`   | -       | Convert to and from `bitcoin` 0.32 (0.32.0 or later) and `miniscript` 12 |
| `bitcoin_latest` | yes     | Alias for `bitcoin_0_32`                                                 |
| `serde`          | -       | Forwards `bip377-ll`'s `serde` feature                                   |

`coordinator` and `signer` are the roles of [`bip377-ll`](bip377-ll/README.md):
enable the one the consumer plays, or both. At least one is required. The
`Backend` trait is always available, so a consumer can implement its own backend;
the `bitcoin_*` features provide the rust-bitcoin one. Without one, `bip377` is the
`bip377::ll` re-export and the `Backend` trait. A new `bitcoin` major release gets
its own feature, and the release features are mutually exclusive.

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
