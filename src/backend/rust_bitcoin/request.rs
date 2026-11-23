use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

use bwk_address::backend::rust_bitcoin::Address;
use miniscript_12::{self as miniscript, DescriptorPublicKey};

use crate::{
    backend::{
        Backend,
        bitcoin::{
            Psbt,
            bip32::{self, Xpub},
            secp256k1,
        },
        rust_bitcoin::RustBitcoin,
    },
    ll::{self, RequestId, SignResponseKind, request::UnregisterDescriptor},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub id: RequestId,
    pub body: Body,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    GetInfo,
    GetKeys(GetKeys),
    RegisterDescriptor(RegisterDescriptor),
    VerifyAddress(VerifyAddress),
    Sign(Sign),
    PrepareNonces(PrepareNonces),
    UnregisterDescriptor(UnregisterDescriptor),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetKeys {
    pub keys: Vec<bip32::DerivationPath>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterDescriptor {
    pub descriptor_alias: String,
    pub descriptor: Option<DescriptorBody>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyAddress {
    pub descriptor_alias: String,
    pub derivation_path: bip32::DerivationPath,
    pub address: Option<Address>,
    pub descriptor: Option<DescriptorBody>,
    pub proof: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sign {
    pub descriptors: Vec<Descriptor>,
    pub psbt: Psbt,
    pub want_kind: Option<SignResponseKind>,
    pub accept_trimmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub alias: String,
    pub descriptor: Option<DescriptorBody>,
    pub proof: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareNonces {
    pub session_id: Option<[u8; 4]>,
    pub session_ref: Option<[u8; 4]>,
    pub descriptor: Option<Descriptor>,
    pub max_inputs: u32,
    pub derivation_path: bip32::DerivationPath,
    pub start: u32,
    pub end: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorBody {
    Bip380(Box<miniscript::Descriptor<DescriptorPublicKey>>),
    Bip388 { keys: Vec<KeyInfo>, policy: String },
    SpKeys(SpKeys),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    pub origin: Option<KeyOrigin>,
    pub xpub: Xpub,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyOrigin {
    pub fingerprint: bip32::Fingerprint,
    pub path: bip32::DerivationPath,
}

impl fmt::Display for KeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(origin) = &self.origin {
            write!(f, "[{}", origin.fingerprint)?;
            for child in &origin.path {
                write!(f, "/{child}")?;
            }
            f.write_str("]")?;
        }
        write!(f, "{}", self.xpub)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpKeys {
    pub fingerprint: bip32::Fingerprint,
    pub spend_path: bip32::DerivationPath,
    pub scan: Scan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scan {
    Path(bip32::DerivationPath),
    Key(secp256k1::SecretKey),
}

impl From<&Request> for ll::Request {
    fn from(request: &Request) -> Self {
        Self {
            id: request.id,
            body: (&request.body).into(),
        }
    }
}

impl From<&Body> for ll::request::Body {
    fn from(body: &Body) -> Self {
        match body {
            Body::GetInfo => Self::GetInfo,
            Body::GetKeys(get_keys) => Self::GetKeys(ll::request::GetKeys {
                keys: get_keys.keys.iter().map(RustBitcoin::to_ll_path).collect(),
            }),
            Body::RegisterDescriptor(register) => {
                Self::RegisterDescriptor(ll::request::RegisterDescriptor {
                    descriptor_alias: register.descriptor_alias.clone(),
                    descriptor: register.descriptor.as_ref().map(Into::into),
                })
            }
            Body::VerifyAddress(verify) => Self::VerifyAddress(verify.into()),
            Body::Sign(sign) => Self::Sign(sign.into()),
            Body::PrepareNonces(prepare) => Self::PrepareNonces(prepare.into()),
            Body::UnregisterDescriptor(unregister) => {
                Self::UnregisterDescriptor(unregister.clone())
            }
        }
    }
}

impl From<&VerifyAddress> for ll::request::VerifyAddress {
    fn from(verify: &VerifyAddress) -> Self {
        Self {
            descriptor_alias: verify.descriptor_alias.clone(),
            derivation_path: RustBitcoin::to_ll_path(&verify.derivation_path),
            address: verify.address.as_ref().map(ll_address),
            descriptor: verify.descriptor.as_ref().map(Into::into),
            proof: verify.proof.clone(),
        }
    }
}

impl From<&Sign> for ll::request::Sign {
    fn from(sign: &Sign) -> Self {
        Self {
            descriptors: sign.descriptors.iter().map(Into::into).collect(),
            psbt: RustBitcoin::to_ll_psbt(&sign.psbt),
            want_kind: sign.want_kind,
            accept_trimmed: sign.accept_trimmed,
        }
    }
}

impl From<&PrepareNonces> for ll::request::PrepareNonces {
    fn from(prepare: &PrepareNonces) -> Self {
        Self {
            session_id: prepare.session_id,
            session_ref: prepare.session_ref,
            descriptor: prepare.descriptor.as_ref().map(Into::into),
            max_inputs: prepare.max_inputs,
            derivation_path: RustBitcoin::to_ll_path(&prepare.derivation_path),
            start: prepare.start,
            end: prepare.end,
        }
    }
}

impl From<&Descriptor> for ll::request::Descriptor {
    fn from(descriptor: &Descriptor) -> Self {
        Self {
            alias: descriptor.alias.clone(),
            descriptor: descriptor.descriptor.as_ref().map(Into::into),
            proof: descriptor.proof.clone(),
        }
    }
}

impl From<&DescriptorBody> for ll::request::DescriptorBody {
    fn from(body: &DescriptorBody) -> Self {
        match body {
            DescriptorBody::Bip380(descriptor) => {
                Self::Bip380(RustBitcoin::to_ll_descriptor(descriptor))
            }
            DescriptorBody::Bip388 { keys, policy } => Self::Bip388 {
                keys: keys.iter().map(ToString::to_string).collect(),
                policy: policy.clone(),
            },
            DescriptorBody::SpKeys(keys) => Self::SpKeys(ll::request::SpKeys {
                fingerprint: RustBitcoin::to_ll_fingerprint(&keys.fingerprint),
                spend_path: RustBitcoin::to_ll_path(&keys.spend_path),
                scan: match &keys.scan {
                    Scan::Path(path) => ll::request::Scan::Path(RustBitcoin::to_ll_path(path)),
                    Scan::Key(key) => ll::request::Scan::Key(RustBitcoin::to_ll_secret_key(key)),
                },
            }),
        }
    }
}

fn ll_address(address: &Address) -> String {
    match address {
        Address::Bitcoin(address) => RustBitcoin::to_ll_address(address),
        Address::SilentPayment(address) => address.to_string(),
    }
}
