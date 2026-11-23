//! The conversions between the codec's wire types and a `bitcoin` release. Each
//! backend implements [`Backend`] over one release; the orphan rule rules out
//! `From` impls between `bip377-ll` types and `bitcoin` ones in this crate.

use alloc::{string::String, vec::Vec};
use core::fmt;

use crate::{
    ll::{
        self,
        types::{
            DerivationPath, ExtendedKey, Fingerprint, MUSIG_PARTIAL_SIG_LEN, PublicKey, SecretKey,
        },
    },
    response::{Mismatch, NotAResponse},
};

#[cfg(feature = "bitcoin_0_32")]
pub use bitcoin_0_32 as bitcoin;

#[cfg(feature = "bitcoin_0_32")]
pub mod rust_bitcoin;

pub trait Backend: fmt::Debug + Clone + PartialEq + Eq {
    type DerivationPath: fmt::Debug + Clone + PartialEq + Eq;
    type Xpub: fmt::Debug + Clone + PartialEq + Eq;
    type Fingerprint: fmt::Debug + Clone + PartialEq + Eq;
    type PublicKey: fmt::Debug + Clone + PartialEq + Eq;
    type SecretKey: fmt::Debug + Clone + PartialEq + Eq;
    type Psbt: fmt::Debug + Clone + PartialEq + Eq;
    type Address: fmt::Debug + Clone + PartialEq + Eq;
    type EcdsaSignature: fmt::Debug + Clone + PartialEq + Eq;
    type TaprootSignature: fmt::Debug + Clone + PartialEq + Eq;
    type XOnlyPublicKey: fmt::Debug + Clone + PartialEq + Eq;
    type TapLeafHash: fmt::Debug + Clone + PartialEq + Eq;
    type MusigPartialSignature: fmt::Debug + Clone + PartialEq + Eq;
    type Descriptor: fmt::Debug + Clone + PartialEq + Eq;
    type Request;
    type Response;
    type Error: fmt::Debug
        + fmt::Display
        + From<ll::encode::Error>
        + From<ll::decode::Error>
        + From<NotAResponse>
        + From<Mismatch>;

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
    fn psbt_input_count(psbt: &Self::Psbt) -> usize;
    fn to_ll_address(address: &Self::Address) -> String;
    fn from_ll_address_uri(uri: &str) -> Result<Self::Address, Self::Error>;
    fn to_ll_descriptor(descriptor: &Self::Descriptor) -> String;
    fn to_ll_xpub_string(xpub: &Self::Xpub) -> String;
    fn from_ll_ecdsa_signature(signature: &[u8]) -> Result<Self::EcdsaSignature, Self::Error>;
    fn from_ll_taproot_signature(signature: &[u8]) -> Result<Self::TaprootSignature, Self::Error>;
    fn from_ll_xonly_public_key(key: &[u8; 32]) -> Result<Self::XOnlyPublicKey, Self::Error>;
    fn from_ll_tap_leaf_hash(hash: &[u8; 32]) -> Self::TapLeafHash;
    fn from_ll_musig_partial_signature(
        signature: &[u8; MUSIG_PARTIAL_SIG_LEN],
    ) -> Result<Self::MusigPartialSignature, Self::Error>;
}
