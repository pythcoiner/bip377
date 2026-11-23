use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

use bwk_address::backend::{Backend as AddressBackend, rust_bitcoin::Address};
use miniscript_12::{Descriptor, DescriptorPublicKey};

use crate::{
    backend::{
        Backend,
        bitcoin::{
            self, Psbt, TapLeafHash, XOnlyPublicKey,
            bip32::{self, ChildNumber, Xpub},
            ecdsa,
            hashes::Hash,
            key::FromSliceError,
            psbt, secp256k1, taproot,
        },
    },
    ll::{
        self,
        types::{
            DerivationPath, ExtendedKey, Fingerprint, MUSIG_PARTIAL_SIG_LEN, PublicKey, SecretKey,
        },
    },
    request::Request,
    response::{Mismatch, NotAResponse, Response},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustBitcoin {}

#[derive(Debug)]
pub enum Error {
    Encode(ll::encode::Error),
    Decode(ll::decode::Error),
    NotAResponse,
    Mismatch(Mismatch),
    AddressUri(bwk_address::backend::rust_bitcoin::Error),
    ExtendedKey(bip32::Error),
    PublicKey(FromSliceError),
    UncompressedPublicKey,
    SecretKey(secp256k1::Error),
    Psbt(psbt::Error),
    EcdsaSignature(ecdsa::Error),
    TaprootSignature(taproot::SigFromSliceError),
    XOnlyPublicKey(secp256k1::Error),
    MusigPartialSignature(secp256k1::scalar::OutOfRangeError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(e) => write!(f, "encode: {e}"),
            Self::Decode(e) => write!(f, "decode: {e}"),
            Self::NotAResponse => f.write_str("expected a response, got a request"),
            Self::Mismatch(e) => e.fmt(f),
            Self::AddressUri(e) => e.fmt(f),
            Self::ExtendedKey(e) => write!(f, "invalid extended key: {e}"),
            Self::PublicKey(e) => write!(f, "invalid public key: {e}"),
            Self::UncompressedPublicKey => f.write_str("public key is not compressed"),
            Self::SecretKey(e) => write!(f, "invalid secret key: {e}"),
            Self::Psbt(e) => write!(f, "invalid PSBT: {e}"),
            Self::EcdsaSignature(e) => write!(f, "invalid ECDSA signature: {e}"),
            Self::TaprootSignature(e) => write!(f, "invalid taproot signature: {e}"),
            Self::XOnlyPublicKey(e) => write!(f, "invalid x-only public key: {e}"),
            Self::MusigPartialSignature(e) => write!(f, "invalid MuSig2 partial signature: {e}"),
        }
    }
}

impl core::error::Error for Error {}

impl From<ll::encode::Error> for Error {
    fn from(error: ll::encode::Error) -> Self {
        Self::Encode(error)
    }
}

impl From<ll::decode::Error> for Error {
    fn from(error: ll::decode::Error) -> Self {
        Self::Decode(error)
    }
}

impl From<NotAResponse> for Error {
    fn from(_: NotAResponse) -> Self {
        Self::NotAResponse
    }
}

impl From<Mismatch> for Error {
    fn from(error: Mismatch) -> Self {
        Self::Mismatch(error)
    }
}

impl Backend for RustBitcoin {
    type DerivationPath = bip32::DerivationPath;
    type Xpub = Xpub;
    type Fingerprint = bip32::Fingerprint;
    type PublicKey = bitcoin::PublicKey;
    type SecretKey = secp256k1::SecretKey;
    type Psbt = Psbt;
    type Address = bwk_address::backend::rust_bitcoin::Address;
    type EcdsaSignature = ecdsa::Signature;
    type TaprootSignature = taproot::Signature;
    type XOnlyPublicKey = XOnlyPublicKey;
    type TapLeafHash = TapLeafHash;
    type MusigPartialSignature = secp256k1::Scalar;
    type Descriptor = Descriptor<DescriptorPublicKey>;
    type Request = Request<Self>;
    type Response = Response<Self>;
    type Error = Error;

    #[cfg(feature = "coordinator")]
    fn encode_request(request: &Request<Self>) -> Result<Vec<u8>, Error> {
        crate::request::encode(request)
    }

    #[cfg(feature = "coordinator")]
    fn decode_response(bytes: &[u8]) -> Result<Response<Self>, Error> {
        crate::response::decode(bytes)
    }

    fn to_ll_path(path: &bip32::DerivationPath) -> DerivationPath {
        DerivationPath(path.into_iter().copied().map(u32::from).collect())
    }

    fn from_ll_path(path: &DerivationPath) -> bip32::DerivationPath {
        path.0.iter().copied().map(ChildNumber::from).collect()
    }

    fn to_ll_xpub(xpub: &Xpub) -> ExtendedKey {
        ExtendedKey(xpub.encode())
    }

    fn from_ll_xpub(key: &ExtendedKey) -> Result<Xpub, Error> {
        Xpub::decode(&key.0).map_err(Error::ExtendedKey)
    }

    fn to_ll_fingerprint(fingerprint: &bip32::Fingerprint) -> Fingerprint {
        Fingerprint(fingerprint.to_bytes())
    }

    fn from_ll_fingerprint(fingerprint: &Fingerprint) -> bip32::Fingerprint {
        bip32::Fingerprint::from(fingerprint.0)
    }

    fn to_ll_public_key(key: &bitcoin::PublicKey) -> Result<PublicKey, Error> {
        if !key.compressed {
            return Err(Error::UncompressedPublicKey);
        }
        Ok(PublicKey(key.inner.serialize()))
    }

    fn from_ll_public_key(key: &PublicKey) -> Result<bitcoin::PublicKey, Error> {
        bitcoin::PublicKey::from_slice(&key.0).map_err(Error::PublicKey)
    }

    fn to_ll_secret_key(key: &secp256k1::SecretKey) -> SecretKey {
        SecretKey(key.secret_bytes())
    }

    fn from_ll_secret_key(key: &SecretKey) -> Result<secp256k1::SecretKey, Error> {
        secp256k1::SecretKey::from_slice(&key.0).map_err(Error::SecretKey)
    }

    fn to_ll_psbt(psbt: &Psbt) -> Vec<u8> {
        psbt.serialize()
    }

    fn from_ll_psbt(psbt: &[u8]) -> Result<Psbt, Error> {
        Psbt::deserialize(psbt).map_err(Error::Psbt)
    }

    fn psbt_input_count(psbt: &Psbt) -> usize {
        psbt.inputs.len()
    }

    fn to_ll_address(address: &Address) -> String {
        match address {
            Address::Bitcoin(address) => address.assume_checked_ref().to_string(),
            Address::SilentPayment(address) => address.to_string(),
        }
    }

    fn from_ll_address_uri(uri: &str) -> Result<Address, Error> {
        <bwk_address::backend::rust_bitcoin::RustBitcoin as AddressBackend>::parse_uri(uri)
            .map_err(Error::AddressUri)
    }

    fn to_ll_descriptor(descriptor: &Descriptor<DescriptorPublicKey>) -> String {
        descriptor.to_string()
    }

    fn to_ll_xpub_string(xpub: &Xpub) -> String {
        xpub.to_string()
    }

    fn from_ll_ecdsa_signature(signature: &[u8]) -> Result<ecdsa::Signature, Error> {
        ecdsa::Signature::from_slice(signature).map_err(Error::EcdsaSignature)
    }

    fn from_ll_taproot_signature(signature: &[u8]) -> Result<taproot::Signature, Error> {
        taproot::Signature::from_slice(signature).map_err(Error::TaprootSignature)
    }

    fn from_ll_xonly_public_key(key: &[u8; 32]) -> Result<XOnlyPublicKey, Error> {
        XOnlyPublicKey::from_slice(key).map_err(Error::XOnlyPublicKey)
    }

    fn from_ll_tap_leaf_hash(hash: &[u8; 32]) -> TapLeafHash {
        TapLeafHash::from_byte_array(*hash)
    }

    fn from_ll_musig_partial_signature(
        signature: &[u8; MUSIG_PARTIAL_SIG_LEN],
    ) -> Result<secp256k1::Scalar, Error> {
        secp256k1::Scalar::from_be_bytes(*signature).map_err(Error::MusigPartialSignature)
    }
}
