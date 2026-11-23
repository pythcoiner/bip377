use alloc::{format, string::String, vec::Vec};

use crate::{
    backend::Backend,
    ll::{self, RequestId, SignResponseKind, request::UnregisterDescriptor},
};

const HARDENED: u32 = 0x8000_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<B: Backend> {
    pub id: RequestId,
    pub body: Body<B>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body<B: Backend> {
    GetInfo,
    GetKeys(GetKeys<B>),
    RegisterDescriptor(RegisterDescriptor<B>),
    VerifyAddress(VerifyAddress<B>),
    Sign(Sign<B>),
    PrepareNonces(PrepareNonces<B>),
    UnregisterDescriptor(UnregisterDescriptor),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetKeys<B: Backend> {
    pub keys: Vec<B::DerivationPath>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterDescriptor<B: Backend> {
    pub descriptor_alias: String,
    pub descriptor: Option<DescriptorBody<B>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyAddress<B: Backend> {
    pub descriptor_alias: String,
    pub derivation_path: B::DerivationPath,
    pub address: Option<B::Address>,
    pub descriptor: Option<DescriptorBody<B>>,
    pub proof: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sign<B: Backend> {
    pub descriptors: Vec<Descriptor<B>>,
    pub psbt: B::Psbt,
    pub want_kind: Option<SignResponseKind>,
    pub accept_trimmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor<B: Backend> {
    pub alias: String,
    pub descriptor: Option<DescriptorBody<B>>,
    pub proof: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareNonces<B: Backend> {
    pub session_id: Option<[u8; 4]>,
    pub session_ref: Option<[u8; 4]>,
    pub descriptor: Option<Descriptor<B>>,
    pub max_inputs: u32,
    pub derivation_path: B::DerivationPath,
    pub start: u32,
    pub end: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorBody<B: Backend> {
    Bip380(B::Descriptor),
    Bip388 {
        keys: Vec<KeyInfo<B>>,
        policy: String,
    },
    SpKeys(SpKeys<B>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo<B: Backend> {
    pub origin: Option<KeyOrigin<B>>,
    pub xpub: B::Xpub,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyOrigin<B: Backend> {
    pub fingerprint: B::Fingerprint,
    pub path: B::DerivationPath,
}

impl<B: Backend> KeyInfo<B> {
    pub fn to_ll_string(&self) -> String {
        let xpub = B::to_ll_xpub_string(&self.xpub);
        let Some(origin) = &self.origin else {
            return xpub;
        };
        let fingerprint: String = B::to_ll_fingerprint(&origin.fingerprint)
            .0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let path: String = B::to_ll_path(&origin.path)
            .0
            .iter()
            .map(|&child| match child & HARDENED {
                0 => format!("/{child}"),
                _ => format!("/{}'", child & !HARDENED),
            })
            .collect();
        format!("[{fingerprint}{path}]{xpub}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpKeys<B: Backend> {
    pub fingerprint: B::Fingerprint,
    pub spend_path: B::DerivationPath,
    pub scan: Scan<B>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scan<B: Backend> {
    Path(B::DerivationPath),
    Key(B::SecretKey),
}

impl<B: Backend> From<&Request<B>> for ll::Request {
    fn from(request: &Request<B>) -> Self {
        Self {
            id: request.id,
            body: (&request.body).into(),
        }
    }
}

impl<B: Backend> From<&Body<B>> for ll::request::Body {
    fn from(body: &Body<B>) -> Self {
        match body {
            Body::GetInfo => Self::GetInfo,
            Body::GetKeys(get_keys) => Self::GetKeys(ll::request::GetKeys {
                keys: get_keys.keys.iter().map(B::to_ll_path).collect(),
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

impl<B: Backend> From<&VerifyAddress<B>> for ll::request::VerifyAddress {
    fn from(verify: &VerifyAddress<B>) -> Self {
        Self {
            descriptor_alias: verify.descriptor_alias.clone(),
            derivation_path: B::to_ll_path(&verify.derivation_path),
            address: verify.address.as_ref().map(B::to_ll_address),
            descriptor: verify.descriptor.as_ref().map(Into::into),
            proof: verify.proof.clone(),
        }
    }
}

impl<B: Backend> From<&Sign<B>> for ll::request::Sign {
    fn from(sign: &Sign<B>) -> Self {
        Self {
            descriptors: sign.descriptors.iter().map(Into::into).collect(),
            psbt: B::to_ll_psbt(&sign.psbt),
            want_kind: sign.want_kind,
            accept_trimmed: sign.accept_trimmed,
        }
    }
}

impl<B: Backend> From<&PrepareNonces<B>> for ll::request::PrepareNonces {
    fn from(prepare: &PrepareNonces<B>) -> Self {
        Self {
            session_id: prepare.session_id,
            session_ref: prepare.session_ref,
            descriptor: prepare.descriptor.as_ref().map(Into::into),
            max_inputs: prepare.max_inputs,
            derivation_path: B::to_ll_path(&prepare.derivation_path),
            start: prepare.start,
            end: prepare.end,
        }
    }
}

impl<B: Backend> From<&Descriptor<B>> for ll::request::Descriptor {
    fn from(descriptor: &Descriptor<B>) -> Self {
        Self {
            alias: descriptor.alias.clone(),
            descriptor: descriptor.descriptor.as_ref().map(Into::into),
            proof: descriptor.proof.clone(),
        }
    }
}

impl<B: Backend> From<&DescriptorBody<B>> for ll::request::DescriptorBody {
    fn from(body: &DescriptorBody<B>) -> Self {
        match body {
            DescriptorBody::Bip380(descriptor) => Self::Bip380(B::to_ll_descriptor(descriptor)),
            DescriptorBody::Bip388 { keys, policy } => Self::Bip388 {
                keys: keys.iter().map(KeyInfo::to_ll_string).collect(),
                policy: policy.clone(),
            },
            DescriptorBody::SpKeys(keys) => Self::SpKeys(ll::request::SpKeys {
                fingerprint: B::to_ll_fingerprint(&keys.fingerprint),
                spend_path: B::to_ll_path(&keys.spend_path),
                scan: match &keys.scan {
                    Scan::Path(path) => ll::request::Scan::Path(B::to_ll_path(path)),
                    Scan::Key(key) => ll::request::Scan::Key(B::to_ll_secret_key(key)),
                },
            }),
        }
    }
}

#[cfg(feature = "coordinator")]
pub fn encode<B: Backend>(request: &Request<B>) -> Result<Vec<u8>, B::Error> {
    Ok(ll::encode_request(&request.into())?)
}
