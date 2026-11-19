//! Codec for draft BIP-377, with conversions to and from a `bitcoin` release.
//!
//! The codec itself lives in [`bip377-ll`](ll), which is dependency-free so a
//! bare-metal signer can depend on it directly. This crate re-exports it and adds
//! [`backend`], the conversions between its wire types and those of the `bitcoin`
//! release selected by a feature flag.

#![no_std]

pub use bip377_ll as ll;

#[cfg(feature = "bitcoin_0_32")]
pub mod backend;
#[cfg(feature = "bitcoin_0_32")]
pub use crate::backend::bitcoin;
