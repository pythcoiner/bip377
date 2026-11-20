# bip377-ll

The binary codec for BIP-377, the signing message encoding between a
coordinator and a signer. [BIP-377](https://github.com/bitcoin/bips/pull/2353) is the authoritative format, extended by the
nonce cache in [NONCE_CACHE.md](../NONCE_CACHE.md) until it lands in the BIP; this
crate implements it and nothing else. Framing (BBQR) and QR rendering are out of scope.

The crate is `no_std` plus `alloc` and pulls no dependency in its default
configuration, so a bare-metal signer can vendor it as-is. `bitcoin` types are
deliberately absent: every one of them is a fixed-size array or an opaque blob on the
wire, so the codec carries `ExtendedKey([u8; 78])`, `Fingerprint([u8; 4])`,
`PublicKey([u8; 33])`, `SecretKey([u8; 32])`, `DerivationPath(Vec<u32>)` and a plain
`Vec<u8>` for the PSBT.
That keeps `secp256k1-sys` and its vendored C off the firmware build.

The conversions between those types and the `bitcoin` ones live in the
[`bip377`](../README.md) crate, one backend per supported `bitcoin` release.

## Features

| Feature flag  | Default | Description                                              |
|---------------|---------|----------------------------------------------------------|
| `coordinator` | yes     | Encode requests and decode responses                     |
| `signer`      | yes     | Decode requests and encode responses                     |
| `ffi`         | -       | The C binding, signer direction; enables `signer`        |

A consumer enables the role it plays, or both: a signer firmware builds with
`default-features = false, features = ["signer"]` and leaves the coordinator half
out. At least one role is required. `decode` reads the header of any message, and
fails with `DirectionDisabled` (`214`) on a direction its features leave out.

`ffi` adds `#[repr(C)]` mirrors of the message tree and four exported functions.

## Rust

```rust
use bip377_ll::{Message, decode, encode_response};

match decode(bytes)? {
    Message::Request(request) => { /* a signer answers it */ }
    Message::Response(response) => { /* a coordinator consumes it */ }
}
let bytes = encode_response(&response)?;
```

Nonce preparation uses `request::Body::PrepareNonces` and
`response::Body::NoncesPrepared` (message code `0x06`). It prepares MuSig2 nonces
for later Signing exchanges. The request carries an optional session ID (absent,
the signer draws one), an optional session reference, an optional descriptor (the
`request::Descriptor` Signing uses), the number of inputs, one derivation path and
a key expression index with an optional inclusive end; the response carries a
`response::Session` (session ID and reference) only when the signer initialized a
new session, then the 66-byte public nonces in order, by key expression index then
input index. Check `Capabilities::supports_nonce_cache()` (bit 8) first. Both encode
and decode check that the number of inputs is at least 1, that the range is ordered
and that a session reference comes with a session ID; decode also rejects a
response carrying only one of the session ID and reference. Signing with a cached
session is ordinary Signing, named inside the PSBT; the signer-side rules live in
the nonce cache BIP draft. [NONCE_CACHE.md](../NONCE_CACHE.md) holds the
BIP-377 side of it until it lands in the BIP.

With `request::Sign::accept_trimmed` set, a `Signed::Psbt` answer may leave out
fields of the request's PSBT, and the coordinator merges it back with the BIP-174
Combiner.

A signatures-only Signing response carries the BIP-375 ECDH shares and BIP-374 DLEQ
proofs of a silent payment send as `SignatureEntry::{SpEcdhShare, SpDleqProof}`, each
scoped to one input or to the whole transaction by `SpScope`. Both encode and decode
reject an ECDSA signature above 73 bytes, a taproot signature that is not 64 or 65 bytes, a share without its proof, a
proof without its share and a duplicate of either; checking that every scan key and
eligible input is covered needs the PSBT, so it is the wallet's job. An entry of a
kind the codec does not know decodes to `SignatureEntry::Unknown` with its raw
fields, and re-encodes unchanged.

Register Descriptor and Address Verification of silent payment keys carry
`request::DescriptorBody::SpKeys`, whose scan key is the signer's own at a path
(`Scan::Path`) or a scan private key it does not hold (`Scan::Key`). Decode rejects
a body with both or neither. `SecretKey`'s `Debug` does not print the key.

Unregister Descriptor (`0x07`) uses `request::Body::UnregisterDescriptor` and
`response::Body::Unregistered`, each carrying only the alias, with the same 32-byte
bound as Register Descriptor.

Get Info (`0x01`) uses `request::Body::GetInfo`, which carries no body, and
`response::Body::Info`. Both encode and decode reject a `max_alias` above 32 and a
`fingerprint` when `state` is not `State::Ready`; an unknown state decodes to
`State::Unknown` and counts as not ready. Encode also rejects reserved `Networks`
bits, which decode keeps as they are.

## C

[`include/bip377.h`](include/bip377.h) is written by hand and
covers the signer direction: decode a request, encode a response. There is no
cbindgen and no build script. `tests/layout.rs` pins the size and alignment of every
mirror type, so a change to the Rust side fails the tests until the header follows.

```c
const bip377_request *request = NULL;
const char *err = NULL;
if (bip377_request_decode(bytes, len, &request, &err) != BIP377_OK) {
    fprintf(stderr, "%s\n", err);
    return 1;
}
/* read request->body.sign.psbt, then answer */
bip377_request_free(request);
```

Ownership: the library never frees your memory, and you never free its memory except
through `bip377_request_free` and `bip377_buf_free`. On encode your struct is
borrowed for the duration of the call only.

The C functions return `BIP377_OK` on success or one of the C binding status codes
from `include/bip377.h` on failure. These codes are not the wire `ERROR`
field from BIP-377; they report local decode, encode, or FFI failures.

```
+-------------------+------------------------+
| Return code range | Source                 |
+-------------------+------------------------+
| 0                 | Success                |
| 100..199          | Byte reader            |
| 200..299          | Protocol decoder       |
| 300..399          | Protocol encoder       |
| 400..499          | C binding              |
| 500..599          | Protocol rule broken   |
+-------------------+------------------------+
```

A message breaking a protocol rule is refused alike by the encoder and the
decoder, with a `500..599` code exposed as `Invalid`. The C request union
includes `prepare_nonces`; a Get Info request has no body and leaves it unused.
The response union includes `nonces_prepared` and `info`. Consumers must rebuild
against the updated header whenever the unions change. Pointer ownership is
unchanged.

A `staticlib` needs a global allocator and a panic handler, which a library cannot
supply, so link this crate as an rlib from your own staticlib crate:

```toml
[lib]
crate-type = ["staticlib"]

[dependencies]
bip377-ll = { version = "0.0.1", default-features = false, features = ["ffi"] }
```

```rust
pub use bip377_ll::ffi::{
    bip377_buf_free, bip377_request_decode, bip377_request_free, bip377_response_encode,
};
```

[`examples/signer.c`](examples/signer.c) is a smoke test against that setup. It is
compiled by hand rather than from CI, which keeps `cc` out of the build:

```sh
cc -I include -Wall -Wextra -o signer examples/signer.c path/to/libyourshim.a
```
