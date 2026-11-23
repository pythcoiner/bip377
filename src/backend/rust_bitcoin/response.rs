use alloc::{string::String, vec::Vec};

use bwk_address::backend::{Backend as AddressBackend, rust_bitcoin::Address};

use crate::{
    backend::{
        Backend,
        bitcoin::{
            Psbt, PublicKey, TapLeafHash, XOnlyPublicKey,
            bip32::{self, Xpub},
            ecdsa, secp256k1, taproot,
        },
        rust_bitcoin::{self, RustBitcoin},
    },
    ll::{
        self, RequestId,
        response::{
            Capabilities, ErrorBody, FirmwareVersion, Networks, NoncesPrepared, Registration,
            SpScope, State, Unregistered,
        },
        types::{DLEQ_PROOF_LEN, MUSIG_PUB_NONCE_LEN},
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub id: RequestId,
    pub body: Body,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Info(Info),
    Keys(Keys),
    Registration(Registration),
    Address(Address),
    Signed(Signed),
    NoncesPrepared(NoncesPrepared),
    Unregistered(Unregistered),
    Error(ErrorBody),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keys {
    pub keys: Vec<Xpub>,
    pub fingerprint: bip32::Fingerprint,
    pub vendor: String,
    pub model: String,
    pub version: FirmwareVersion,
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    pub vendor: String,
    pub model: String,
    pub version: FirmwareVersion,
    pub capabilities: Capabilities,
    pub state: State,
    pub networks: Networks,
    pub max_message: u32,
    pub max_alias: u8,
    pub fingerprint: Option<bip32::Fingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signed {
    Psbt(Psbt),
    Signatures(Vec<SignatureEntry>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureEntry {
    Ecdsa {
        input_index: u32,
        public_key: PublicKey,
        signature: ecdsa::Signature,
    },
    TapKey {
        input_index: u32,
        signature: taproot::Signature,
    },
    TapScript {
        input_index: u32,
        xonly_public_key: XOnlyPublicKey,
        tap_leaf_hash: TapLeafHash,
        signature: taproot::Signature,
    },
    MusigPubNonce {
        input_index: u32,
        participant: PublicKey,
        aggregate: PublicKey,
        leaf_hash: Option<TapLeafHash>,
        nonce: [u8; MUSIG_PUB_NONCE_LEN],
    },
    MusigPartialSig {
        input_index: u32,
        participant: PublicKey,
        aggregate: PublicKey,
        leaf_hash: Option<TapLeafHash>,
        signature: secp256k1::Scalar,
    },
    SpEcdhShare {
        scope: SpScope,
        scan_key: PublicKey,
        share: PublicKey,
    },
    SpDleqProof {
        scope: SpScope,
        scan_key: PublicKey,
        proof: [u8; DLEQ_PROOF_LEN],
    },
    Unknown {
        input_index: u32,
        kind: u8,
        fields: Vec<u8>,
    },
}

impl TryFrom<ll::Response> for Response {
    type Error = rust_bitcoin::Error;

    fn try_from(response: ll::Response) -> Result<Self, rust_bitcoin::Error> {
        Ok(Self {
            id: response.id,
            body: response.body.try_into()?,
        })
    }
}

impl TryFrom<ll::response::Body> for Body {
    type Error = rust_bitcoin::Error;

    fn try_from(body: ll::response::Body) -> Result<Self, rust_bitcoin::Error> {
        Ok(match body {
            ll::response::Body::Info(info) => Self::Info(info.into()),
            ll::response::Body::Keys(keys) => Self::Keys(keys.try_into()?),
            ll::response::Body::Registration(registration) => Self::Registration(registration),
            ll::response::Body::AddressUri(address) => Self::Address(
                <bwk_address::backend::rust_bitcoin::RustBitcoin as AddressBackend>::parse_uri(
                    &address.uri,
                )
                .map_err(rust_bitcoin::Error::AddressUri)?,
            ),
            ll::response::Body::Signed(signed) => Self::Signed(signed.try_into()?),
            ll::response::Body::NoncesPrepared(nonces) => Self::NoncesPrepared(nonces),
            ll::response::Body::Unregistered(unregistered) => Self::Unregistered(unregistered),
            ll::response::Body::Error(error) => Self::Error(error),
        })
    }
}

impl From<ll::response::Info> for Info {
    fn from(info: ll::response::Info) -> Self {
        Self {
            vendor: info.vendor,
            model: info.model,
            version: info.version,
            capabilities: info.capabilities,
            state: info.state,
            networks: info.networks,
            max_message: info.max_message,
            max_alias: info.max_alias,
            fingerprint: info
                .fingerprint
                .as_ref()
                .map(RustBitcoin::from_ll_fingerprint),
        }
    }
}

impl TryFrom<ll::response::Keys> for Keys {
    type Error = rust_bitcoin::Error;

    fn try_from(keys: ll::response::Keys) -> Result<Self, rust_bitcoin::Error> {
        Ok(Self {
            keys: keys
                .keys
                .iter()
                .map(RustBitcoin::from_ll_xpub)
                .collect::<Result<_, _>>()?,
            fingerprint: RustBitcoin::from_ll_fingerprint(&keys.fingerprint),
            vendor: keys.vendor,
            model: keys.model,
            version: keys.version,
            capabilities: keys.capabilities,
        })
    }
}

impl TryFrom<ll::response::Signed> for Signed {
    type Error = rust_bitcoin::Error;

    fn try_from(signed: ll::response::Signed) -> Result<Self, rust_bitcoin::Error> {
        match signed {
            ll::response::Signed::Psbt(psbt) => Ok(Self::Psbt(RustBitcoin::from_ll_psbt(&psbt)?)),
            ll::response::Signed::Signatures(entries) => Ok(Self::Signatures(
                entries
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<_, _>>()?,
            )),
        }
    }
}

impl TryFrom<ll::response::SignatureEntry> for SignatureEntry {
    type Error = rust_bitcoin::Error;

    fn try_from(entry: ll::response::SignatureEntry) -> Result<Self, rust_bitcoin::Error> {
        use crate::ll::response::SignatureEntry as WireEntry;
        Ok(match entry {
            WireEntry::Ecdsa {
                input_index,
                public_key,
                signature,
            } => Self::Ecdsa {
                input_index,
                public_key: RustBitcoin::from_ll_public_key(&public_key)?,
                signature: RustBitcoin::from_ll_ecdsa_signature(&signature)?,
            },
            WireEntry::TapKey {
                input_index,
                signature,
            } => Self::TapKey {
                input_index,
                signature: RustBitcoin::from_ll_taproot_signature(&signature)?,
            },
            WireEntry::TapScript {
                input_index,
                xonly_public_key,
                tap_leaf_hash,
                signature,
            } => Self::TapScript {
                input_index,
                xonly_public_key: RustBitcoin::from_ll_xonly_public_key(&xonly_public_key)?,
                tap_leaf_hash: RustBitcoin::from_ll_tap_leaf_hash(&tap_leaf_hash),
                signature: RustBitcoin::from_ll_taproot_signature(&signature)?,
            },
            WireEntry::MusigPubNonce {
                input_index,
                participant,
                aggregate,
                leaf_hash,
                nonce,
            } => Self::MusigPubNonce {
                input_index,
                participant: RustBitcoin::from_ll_public_key(&participant)?,
                aggregate: RustBitcoin::from_ll_public_key(&aggregate)?,
                leaf_hash: leaf_hash.as_ref().map(RustBitcoin::from_ll_tap_leaf_hash),
                nonce,
            },
            WireEntry::MusigPartialSig {
                input_index,
                participant,
                aggregate,
                leaf_hash,
                signature,
            } => Self::MusigPartialSig {
                input_index,
                participant: RustBitcoin::from_ll_public_key(&participant)?,
                aggregate: RustBitcoin::from_ll_public_key(&aggregate)?,
                leaf_hash: leaf_hash.as_ref().map(RustBitcoin::from_ll_tap_leaf_hash),
                signature: RustBitcoin::from_ll_musig_partial_signature(&signature)?,
            },
            WireEntry::SpEcdhShare {
                scope,
                scan_key,
                share,
            } => Self::SpEcdhShare {
                scope,
                scan_key: RustBitcoin::from_ll_public_key(&scan_key)?,
                share: RustBitcoin::from_ll_public_key(&share)?,
            },
            WireEntry::SpDleqProof {
                scope,
                scan_key,
                proof,
            } => Self::SpDleqProof {
                scope,
                scan_key: RustBitcoin::from_ll_public_key(&scan_key)?,
                proof,
            },
            WireEntry::Unknown {
                input_index,
                kind,
                fields,
            } => Self::Unknown {
                input_index,
                kind,
                fields,
            },
        })
    }
}
