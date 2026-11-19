# bip377

Rust implementation of [BIP-377](https://github.com/bitcoin/bips/pull/2353), the
byte encoding of the messages a coordinator and a signer exchange: Get Info, Get
Keys, Register Descriptor, Address Verification, Signing and Unregister
Descriptor. The encoding is transport agnostic, so how the bytes are carried
(animated QR, USB, NFC, a file) is out of scope.

The BIP is a draft and this crate is still empty. The code is coming soon.

## License

MIT, see [LICENSE](LICENSE).
