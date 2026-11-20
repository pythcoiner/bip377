# Pending changes to BIP-377: nonce cache

This codec implements the nonce cache ahead of
[BIP-377](https://github.com/bitcoin/bips/pull/2353). These changes will move into
BIP-377 once the nonce cache BIP draft ("Signer nonce cache sessions for one-round
signing") has its own draft PR, and this file will be removed then.

Each section below names the BIP-377 section it changes. Everything else follows
BIP-377 as it is.

## Overview / Operations

Add a row between `0x05` and `0x07`:

```
| 0x06   | Nonce Preparation     | Prepare public nonces for later Signing      |
|        |                       | exchanges                                    |
```

## Message Type

Add `0x06` to the `TYPE` values:

```
| 0x06  | Nonce Preparation     |
```

`0x06` is no longer reserved: "Values `0x08`–`0x3F` are reserved."

## Common Field Encodings (`CAPABILITIES`)

Bit 8 is no longer reserved:

```
| 8     | Nonce cache                              |
| 9–30  | Reserved for future capabilities         |
```

Add after the bit 7 paragraph:

> Bit 8 advertises the Nonce Preparation operation below. It also means a Signing
> `PSBT` may name a cached nonce session for MuSig2, as the nonce cache BIP draft
> ("Signer nonce cache sessions for one-round signing") defines.

The reserved range paragraph starts "Bits 9–30 are reserved for future capabilities".

The `ERROR` `0x0E` examples gain one: "..., a `musig()` key without bit 7, or a
Nonce Preparation request without bit 8."

## Error response body

`ERROR` `0x0C` becomes:

```
| 0x0C      | Session missing, consumed or mismatched              |
```

## Signing / MuSig2

The list of what the `PSBT` selects becomes:

> - The `PSBT` carries `PSBT_GLOBAL_NONCE_CACHE_SESSION` (signer advertising
>   capability bit 8): the partial signature (`SIG_KIND` `0x05`) of each of its
>   MuSig2 signatures, in one round as the nonce cache BIP draft defines.
> - Otherwise, the `PSBT` has no `PSBT_IN_MUSIG2_PUB_NONCE` (`0x1b`) for the key of
>   one of its MuSig2 signatures: the public nonce (`SIG_KIND` `0x04`) of each of its
>   MuSig2 signatures, and no signature of any kind.[^round1]
> - Otherwise: the partial signature (`SIG_KIND` `0x05`) of each of its MuSig2
>   signatures for which the `PSBT` has a `PSBT_IN_MUSIG2_PUB_NONCE` from every
>   participant, nothing for the others.
>
> The last two are the two rounds of the nonce cache BIP draft. With `KIND` `0x01`
> the same values go in the `PSBT`. A session missing, consumed or mismatched is
> refused with `ERROR` `0x0C`. So is a Signing request naming a nonce cache session
> whose `PSBT` carries, for the signer's own key, a `PSBT_IN_MUSIG2_PUB_NONCE`
> (`0x1b`) that session did not prepare.
>
> [^round1]: **Why a public nonce for every MuSig2 signature?**
>     Round 1 of the nonce cache two-round flow draws a new secret, so a nonce
>     returned earlier for another key would no longer match it.

## Nonce Preparation (new section, after Signing)

> This operation requires capability bit 8 and has `TYPE` `0x06`. A signer without
> bit 8 MUST answer it with `ERROR` `0x0E`. It prepares public nonces for later
> Signing exchanges, the nonce cache BIP draft being one use. No root, secret nonce
> or other secret material may appear in these messages.
>
> **Request:**
>
> `SESSION_ID` `SESSION_REF` `DESCRIPTOR` `MAX_INPUTS` `DERIVATION_PATH` `START` `END`
>
> - `SESSION_ID`: OPTIONAL, 4 opaque bytes chosen by the coordinator. Absent, the
>   signer draws one.
> - `SESSION_REF`: OPTIONAL, 4 bytes, the session reference from the answer that
>   initialized the session of this `SESSION_ID`. The coordinator SHOULD send it when
>   it already holds nonces of this `SESSION_ID`: on a mismatch the signer then
>   refuses, rather than drawing a new session in place of the previous one.
> - `DESCRIPTOR`: OPTIONAL, a `DESCRIPTOR` as in Signing, the descriptor the nonces
>   are for, for a signer whose sessions depend on it.
> - `MAX_INPUTS`: a 4-byte big-endian unsigned integer, the number of inputs, at
>   least 1.
> - `DERIVATION_PATH`: the key's path from the master key.
> - `START`: a 4-byte big-endian unsigned integer, the first key expression index.
> - `END`: OPTIONAL, a 4-byte big-endian unsigned integer, the last key expression
>   index. Absent, only `START` is requested.
>
> `START` MUST NOT exceed `END` when `END` is present. The range lets the coordinator
> fetch a session in chunks. A reader MUST reject a request carrying `SESSION_REF`
> without `SESSION_ID`.
>
> A signer MUST refuse a request whose `SESSION_REF` does not match its stored session
> for `SESSION_ID`, or names a session it does not hold, with `ERROR` `0x0C`, and MUST
> NOT create a new session for it.
>
> The signer initializes a new session for a request without `SESSION_ID`, under the
> `SESSION_ID` it draws, and for a request without `SESSION_REF` whose `SESSION_ID`
> names no session it holds.
>
> **Ok response:**
>
> `SESSION_ID` `SESSION_REF` `NONCES`
>
> - `SESSION_ID`: OPTIONAL, 4 bytes, the request's `SESSION_ID`, or the one the signer
>   drew.
> - `SESSION_REF`: OPTIONAL, 4 bytes, the reference of the new session.
> - `NONCES`: a vector of 66-byte BIP-327 public nonces, each without a length
>   prefix: (`END` minus `START` plus 1, or 1 when `END` is absent) times `MAX_INPUTS`
>   entries, with the values of the request it answers.
>
> `SESSION_ID` and `SESSION_REF` are both present when the signer initialized a new
> session for the request, and both absent when the nonces come from a session it
> already held. A reader MUST reject a response carrying exactly one of them. The
> coordinator pairs the response with its request by `REQUEST_ID`.
>
> Entries are positional, ordered by key expression index then by input index: the
> nonce for key expression index `j` and input index `i` is entry
> (`j` minus the request's `START`) times its `MAX_INPUTS` plus `i`.

## Test Vectors

[`test_vectors/nonce_cache.json`](test_vectors/nonce_cache.json) is new:

> - `nonce_cache.json`: Nonce Preparation request/response, including a request
>   with a `DESCRIPTOR`, one without `END`, one without `SESSION_ID`, and responses
>   for a new session (`SESSION_ID` and `SESSION_REF` present) and for an existing
>   one (both absent).

The `errors.json` item of the list describes `0x0C` as "(session)" instead of
"(MuSig2 session)"; the file itself is unchanged.

[`test_vectors/invalid.json`](test_vectors/invalid.json) has five more vectors:
`invalid_presence`, `invalid_nonce_max_inputs_zero`, `invalid_nonce_start_after_end`,
`invalid_nonce_session_ref_without_id` and `invalid_nonce_response_id_only`. The
`invalid.json` item of the list adds "an invalid `PRESENCE`" and "a Nonce Preparation
request with `MAX_INPUTS` `0`, `START` above `END` or `SESSION_REF` without
`SESSION_ID`, a Nonce Preparation response with only one of `SESSION_ID` and
`SESSION_REF`".
