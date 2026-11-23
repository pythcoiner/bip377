use alloc::{string::String, vec::Vec};

use core::fmt;

use crate::{
    backend::Backend,
    ll::{
        self, MessageType, RequestId,
        response::{
            Capabilities, ErrorBody, FirmwareVersion, Networks, NoncesPrepared, Registration,
            SpScope, State, Unregistered,
        },
        types::{DLEQ_PROOF_LEN, MUSIG_PUB_NONCE_LEN},
    },
};

#[cfg(feature = "coordinator")]
use crate::request::{self, Request};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response<B: Backend> {
    pub id: RequestId,
    pub body: Body<B>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body<B: Backend> {
    Info(Info<B>),
    Keys(Keys<B>),
    Registration(Registration),
    Address(B::Address),
    Signed(Signed<B>),
    NoncesPrepared(NoncesPrepared),
    Unregistered(Unregistered),
    Error(ErrorBody),
}

impl<B: Backend> Body<B> {
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::Info(_) => MessageType::GetInfo,
            Self::Keys(_) => MessageType::GetKeys,
            Self::Registration(_) => MessageType::RegisterDescriptor,
            Self::Address(_) => MessageType::AddressVerification,
            Self::Signed(_) => MessageType::Signing,
            Self::NoncesPrepared(_) => MessageType::NoncePreparation,
            Self::Unregistered(_) => MessageType::UnregisterDescriptor,
            Self::Error(error) => error.message_type,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keys<B: Backend> {
    pub keys: Vec<B::Xpub>,
    pub fingerprint: B::Fingerprint,
    pub vendor: String,
    pub model: String,
    pub version: FirmwareVersion,
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info<B: Backend> {
    pub vendor: String,
    pub model: String,
    pub version: FirmwareVersion,
    pub capabilities: Capabilities,
    pub state: State,
    pub networks: Networks,
    pub max_message: u32,
    pub max_alias: u8,
    pub fingerprint: Option<B::Fingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signed<B: Backend> {
    Psbt(B::Psbt),
    Signatures(Vec<SignatureEntry<B>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureEntry<B: Backend> {
    Ecdsa {
        input_index: u32,
        public_key: B::PublicKey,
        signature: B::EcdsaSignature,
    },
    TapKey {
        input_index: u32,
        signature: B::TaprootSignature,
    },
    TapScript {
        input_index: u32,
        xonly_public_key: B::XOnlyPublicKey,
        tap_leaf_hash: B::TapLeafHash,
        signature: B::TaprootSignature,
    },
    MusigPubNonce {
        input_index: u32,
        participant: B::PublicKey,
        aggregate: B::PublicKey,
        leaf_hash: Option<B::TapLeafHash>,
        nonce: [u8; MUSIG_PUB_NONCE_LEN],
    },
    MusigPartialSig {
        input_index: u32,
        participant: B::PublicKey,
        aggregate: B::PublicKey,
        leaf_hash: Option<B::TapLeafHash>,
        signature: B::MusigPartialSignature,
    },
    SpEcdhShare {
        scope: SpScope,
        scan_key: B::PublicKey,
        share: B::PublicKey,
    },
    SpDleqProof {
        scope: SpScope,
        scan_key: B::PublicKey,
        proof: [u8; DLEQ_PROOF_LEN],
    },
    Unknown {
        input_index: u32,
        kind: u8,
        fields: Vec<u8>,
    },
}

impl<B: Backend> SignatureEntry<B> {
    pub fn input_index(&self) -> Option<u32> {
        match self {
            Self::Ecdsa { input_index, .. }
            | Self::TapKey { input_index, .. }
            | Self::TapScript { input_index, .. }
            | Self::MusigPubNonce { input_index, .. }
            | Self::MusigPartialSig { input_index, .. }
            | Self::Unknown { input_index, .. } => Some(*input_index),
            Self::SpEcdhShare { .. } | Self::SpDleqProof { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotAResponse;

impl fmt::Display for NotAResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a response, got a request")
    }
}

impl core::error::Error for NotAResponse {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mismatch {
    RequestId {
        expected: RequestId,
        received: RequestId,
    },
    MessageType {
        expected: MessageType,
        received: MessageType,
    },
    KeyCount {
        expected: usize,
        received: usize,
    },
    Alias {
        expected: String,
        received: String,
    },
    Address {
        expected: String,
        received: String,
    },
    InputIndex {
        index: u32,
        inputs: usize,
    },
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestId { expected, received } => write!(
                f,
                "expected a response to request {expected:?}, got one to {received:?}"
            ),
            Self::MessageType { expected, received } => {
                write!(f, "expected a {expected:?} response, got {received:?}")
            }
            Self::KeyCount { expected, received } => {
                write!(
                    f,
                    "{expected} keys were asked for, {received} were returned"
                )
            }
            Self::Alias { expected, received } => {
                write!(f, "expected alias {expected}, got {received}")
            }
            Self::Address { expected, received } => {
                write!(f, "expected address {expected}, got {received}")
            }
            Self::InputIndex { index, inputs } => write!(
                f,
                "signature names input {index}, the transaction has {inputs} inputs"
            ),
        }
    }
}

impl core::error::Error for Mismatch {}

#[cfg(feature = "coordinator")]
pub fn decode<B: Backend>(bytes: &[u8]) -> Result<Response<B>, B::Error> {
    match ll::decode(bytes)? {
        ll::Message::Response(response) => response.try_into(),
        ll::Message::Request(_) => Err(NotAResponse.into()),
    }
}

#[cfg(feature = "coordinator")]
pub fn validate<B: Backend>(request: &Request<B>, response: &Response<B>) -> Result<(), B::Error> {
    let expected = request.body.message_type();
    let received = response.body.message_type();
    if received == MessageType::UnreadableRequest {
        return Ok(());
    }
    if response.id != request.id {
        return Err(Mismatch::RequestId {
            expected: request.id,
            received: response.id,
        }
        .into());
    }
    if received != expected {
        return Err(Mismatch::MessageType { expected, received }.into());
    }
    match (&request.body, &response.body) {
        (request::Body::GetKeys(get_keys), Body::Keys(keys))
            if keys.keys.len() != get_keys.keys.len() =>
        {
            Err(Mismatch::KeyCount {
                expected: get_keys.keys.len(),
                received: keys.keys.len(),
            }
            .into())
        }
        (request::Body::RegisterDescriptor(register), Body::Registration(registration))
            if registration.descriptor_alias != register.descriptor_alias =>
        {
            Err(Mismatch::Alias {
                expected: register.descriptor_alias.clone(),
                received: registration.descriptor_alias.clone(),
            }
            .into())
        }
        (
            request::Body::VerifyAddress(request::VerifyAddress {
                address: Some(expected),
                ..
            }),
            Body::Address(received),
        ) if received != expected => Err(Mismatch::Address {
            expected: B::to_ll_address(expected),
            received: B::to_ll_address(received),
        }
        .into()),
        (request::Body::Sign(sign), Body::Signed(Signed::Signatures(entries))) => {
            let inputs = B::psbt_input_count(&sign.psbt);
            match entries
                .iter()
                .filter_map(SignatureEntry::input_index)
                .find(|&index| index as usize >= inputs)
            {
                Some(index) => Err(Mismatch::InputIndex { index, inputs }.into()),
                None => Ok(()),
            }
        }
        _ => Ok(()),
    }
}

impl<B: Backend> TryFrom<ll::Response> for Response<B> {
    type Error = B::Error;

    fn try_from(response: ll::Response) -> Result<Self, B::Error> {
        Ok(Self {
            id: response.id,
            body: response.body.try_into()?,
        })
    }
}

impl<B: Backend> TryFrom<ll::response::Body> for Body<B> {
    type Error = B::Error;

    fn try_from(body: ll::response::Body) -> Result<Self, B::Error> {
        Ok(match body {
            ll::response::Body::Info(info) => Self::Info(info.into()),
            ll::response::Body::Keys(keys) => Self::Keys(keys.try_into()?),
            ll::response::Body::Registration(registration) => Self::Registration(registration),
            ll::response::Body::AddressUri(address) => {
                Self::Address(B::from_ll_address_uri(&address.uri)?)
            }
            ll::response::Body::Signed(signed) => Self::Signed(signed.try_into()?),
            ll::response::Body::NoncesPrepared(nonces) => Self::NoncesPrepared(nonces),
            ll::response::Body::Unregistered(unregistered) => Self::Unregistered(unregistered),
            ll::response::Body::Error(error) => Self::Error(error),
        })
    }
}

impl<B: Backend> From<ll::response::Info> for Info<B> {
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
            fingerprint: info.fingerprint.as_ref().map(B::from_ll_fingerprint),
        }
    }
}

impl<B: Backend> TryFrom<ll::response::Keys> for Keys<B> {
    type Error = B::Error;

    fn try_from(keys: ll::response::Keys) -> Result<Self, B::Error> {
        Ok(Self {
            keys: keys
                .keys
                .iter()
                .map(B::from_ll_xpub)
                .collect::<Result<_, _>>()?,
            fingerprint: B::from_ll_fingerprint(&keys.fingerprint),
            vendor: keys.vendor,
            model: keys.model,
            version: keys.version,
            capabilities: keys.capabilities,
        })
    }
}

impl<B: Backend> TryFrom<ll::response::Signed> for Signed<B> {
    type Error = B::Error;

    fn try_from(signed: ll::response::Signed) -> Result<Self, B::Error> {
        match signed {
            ll::response::Signed::Psbt(psbt) => Ok(Self::Psbt(B::from_ll_psbt(&psbt)?)),
            ll::response::Signed::Signatures(entries) => Ok(Self::Signatures(
                entries
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<_, _>>()?,
            )),
        }
    }
}

impl<B: Backend> TryFrom<ll::response::SignatureEntry> for SignatureEntry<B> {
    type Error = B::Error;

    fn try_from(entry: ll::response::SignatureEntry) -> Result<Self, B::Error> {
        use crate::ll::response::SignatureEntry as WireEntry;
        Ok(match entry {
            WireEntry::Ecdsa {
                input_index,
                public_key,
                signature,
            } => Self::Ecdsa {
                input_index,
                public_key: B::from_ll_public_key(&public_key)?,
                signature: B::from_ll_ecdsa_signature(&signature)?,
            },
            WireEntry::TapKey {
                input_index,
                signature,
            } => Self::TapKey {
                input_index,
                signature: B::from_ll_taproot_signature(&signature)?,
            },
            WireEntry::TapScript {
                input_index,
                xonly_public_key,
                tap_leaf_hash,
                signature,
            } => Self::TapScript {
                input_index,
                xonly_public_key: B::from_ll_xonly_public_key(&xonly_public_key)?,
                tap_leaf_hash: B::from_ll_tap_leaf_hash(&tap_leaf_hash),
                signature: B::from_ll_taproot_signature(&signature)?,
            },
            WireEntry::MusigPubNonce {
                input_index,
                participant,
                aggregate,
                leaf_hash,
                nonce,
            } => Self::MusigPubNonce {
                input_index,
                participant: B::from_ll_public_key(&participant)?,
                aggregate: B::from_ll_public_key(&aggregate)?,
                leaf_hash: leaf_hash.as_ref().map(B::from_ll_tap_leaf_hash),
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
                participant: B::from_ll_public_key(&participant)?,
                aggregate: B::from_ll_public_key(&aggregate)?,
                leaf_hash: leaf_hash.as_ref().map(B::from_ll_tap_leaf_hash),
                signature: B::from_ll_musig_partial_signature(&signature)?,
            },
            WireEntry::SpEcdhShare {
                scope,
                scan_key,
                share,
            } => Self::SpEcdhShare {
                scope,
                scan_key: B::from_ll_public_key(&scan_key)?,
                share: B::from_ll_public_key(&share)?,
            },
            WireEntry::SpDleqProof {
                scope,
                scan_key,
                proof,
            } => Self::SpDleqProof {
                scope,
                scan_key: B::from_ll_public_key(&scan_key)?,
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
