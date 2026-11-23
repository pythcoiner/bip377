//! The conversions between the codec's wire types and a `bitcoin` release. Each
//! backend implements [`Backend`] over one release; the orphan rule rules out
//! `From` impls between `bip377-ll` types and `bitcoin` ones in this crate.

use alloc::{string::String, vec::Vec};
use core::fmt;

use crate::ll::types::{
    DerivationPath, ExtendedKey, Fingerprint, MUSIG_PARTIAL_SIG_LEN, PublicKey, SecretKey,
};

#[cfg(feature = "bitcoin_0_32")]
pub use bitcoin_0_32 as bitcoin;

#[cfg(feature = "bitcoin_0_32")]
pub mod rust_bitcoin;

pub trait Backend {
    type DerivationPath;
    type Xpub;
    type Fingerprint;
    type PublicKey;
    type SecretKey;
    type Psbt;
    type Address;
    type EcdsaSignature;
    type TaprootSignature;
    type XOnlyPublicKey;
    type TapLeafHash;
    type MusigPartialSignature;
    type Descriptor;
    type Request;
    type Response;
    type Error: fmt::Debug + fmt::Display;

    #[cfg(feature = "coordinator")]
    fn encode_request(request: &Self::Request) -> Result<Vec<u8>, Self::Error>;
    #[cfg(feature = "coordinator")]
    fn decode_response(bytes: &[u8]) -> Result<Self::Response, Self::Error>;

    fn to_ll_path(path: &Self::DerivationPath) -> DerivationPath;
    fn from_ll_path(path: &DerivationPath) -> Self::DerivationPath;
    fn to_ll_xpub(xpub: &Self::Xpub) -> ExtendedKey;
    fn from_ll_xpub(key: &ExtendedKey) -> Result<Self::Xpub, Self::Error>;
    fn to_ll_fingerprint(fingerprint: &Self::Fingerprint) -> Fingerprint;
    fn from_ll_fingerprint(fingerprint: &Fingerprint) -> Self::Fingerprint;
    /// The wire carries compressed keys only, so an uncompressed one is an error.
    fn to_ll_public_key(key: &Self::PublicKey) -> Result<PublicKey, Self::Error>;
    fn from_ll_public_key(key: &PublicKey) -> Result<Self::PublicKey, Self::Error>;
    fn to_ll_secret_key(key: &Self::SecretKey) -> SecretKey;
    fn from_ll_secret_key(key: &SecretKey) -> Result<Self::SecretKey, Self::Error>;
    fn to_ll_psbt(psbt: &Self::Psbt) -> Vec<u8>;
    fn from_ll_psbt(psbt: &[u8]) -> Result<Self::Psbt, Self::Error>;
    fn to_ll_address(address: &Self::Address) -> String;
    fn to_ll_descriptor(descriptor: &Self::Descriptor) -> String;
    fn from_ll_address(address: &str) -> Result<Self::Address, Self::Error>;
    fn from_ll_ecdsa_signature(signature: &[u8]) -> Result<Self::EcdsaSignature, Self::Error>;
    fn from_ll_taproot_signature(signature: &[u8]) -> Result<Self::TaprootSignature, Self::Error>;
    fn from_ll_xonly_public_key(key: &[u8; 32]) -> Result<Self::XOnlyPublicKey, Self::Error>;
    fn from_ll_tap_leaf_hash(hash: &[u8; 32]) -> Self::TapLeafHash;
    fn from_ll_musig_partial_signature(
        signature: &[u8; MUSIG_PARTIAL_SIG_LEN],
    ) -> Result<Self::MusigPartialSignature, Self::Error>;
}
