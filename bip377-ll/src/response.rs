use alloc::{string::String, vec::Vec};

use crate::{
    Invalid, MAX_DESCRIPTOR_ALIAS, MessageType, sp,
    types::{
        DLEQ_PROOF_LEN, ECDSA_SIGNATURE_MAX_LEN, ExtendedKey, Fingerprint, MUSIG_PARTIAL_SIG_LEN,
        MUSIG_PUB_NONCE_LEN, PublicKey, SCHNORR_SIGNATURE_LEN,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Info(Info),
    Keys(Keys),
    Registration(Registration),
    AddressUri(AddressUri),
    Signed(Signed),
    NoncesPrepared(NoncesPrepared),
    Unregistered(Unregistered),
    Error(ErrorBody),
}

impl Body {
    pub fn message_type(&self) -> MessageType {
        self.into()
    }
}

impl From<&Body> for MessageType {
    fn from(body: &Body) -> Self {
        match body {
            Body::Info(_) => Self::GetInfo,
            Body::Keys(_) => Self::GetKeys,
            Body::Registration(_) => Self::RegisterDescriptor,
            Body::AddressUri(_) => Self::AddressVerification,
            Body::Signed(_) => Self::Signing,
            Body::NoncesPrepared(_) => Self::NoncePreparation,
            Body::Unregistered(_) => Self::UnregisterDescriptor,
            Body::Error(e) => e.message_type,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keys {
    pub keys: Vec<ExtendedKey>,
    pub fingerprint: Fingerprint,
    pub vendor: String,
    pub model: String,
    pub version: FirmwareVersion,
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FirmwareVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub flag: ReleaseFlag,
}

/// A pre-release channel and its number, the two `FLAG` bytes. A stable release has
/// no number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ReleaseFlag {
    Stable,
    Alpha(u8),
    Beta(u8),
    ReleaseCandidate(u8),
    Unknown { channel: u8, number: u8 },
}

impl ReleaseFlag {
    pub fn bytes(self) -> [u8; 2] {
        self.into()
    }
}

impl From<ReleaseFlag> for [u8; 2] {
    fn from(flag: ReleaseFlag) -> Self {
        match flag {
            ReleaseFlag::Stable => [0x00, 0x00],
            ReleaseFlag::Alpha(number) => [0x01, number],
            ReleaseFlag::Beta(number) => [0x02, number],
            ReleaseFlag::ReleaseCandidate(number) => [0x03, number],
            ReleaseFlag::Unknown { channel, number } => [channel, number],
        }
    }
}

impl TryFrom<[u8; 2]> for ReleaseFlag {
    type Error = Invalid;

    fn try_from([channel, number]: [u8; 2]) -> Result<Self, Self::Error> {
        match channel {
            0x00 if number != 0 => Err(Invalid::NumberedStableRelease(number)),
            0x00 => Ok(Self::Stable),
            0x01 => Ok(Self::Alpha(number)),
            0x02 => Ok(Self::Beta(number)),
            0x03 => Ok(Self::ReleaseCandidate(number)),
            channel => Ok(Self::Unknown { channel, number }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Capabilities(pub u32);

impl Capabilities {
    pub const BIP380_DESCRIPTORS: u32 = 1 << 0;
    pub const BIP388_WALLET_POLICIES: u32 = 1 << 1;
    pub const MINISCRIPT_SEGWIT_V0: u32 = 1 << 2;
    pub const MINISCRIPT_TAPROOT: u32 = 1 << 3;
    pub const SILENT_PAYMENT_SENDS: u32 = 1 << 4;
    pub const SILENT_PAYMENT_ACCOUNTS: u32 = 1 << 5;
    pub const UNREGISTER_DESCRIPTOR: u32 = 1 << 6;
    pub const MUSIG2: u32 = 1 << 7;
    pub const NONCE_CACHE: u32 = 1 << 8;
    /// Every bit this version defines.
    pub const DEFINED: u32 = Self::BIP380_DESCRIPTORS
        | Self::BIP388_WALLET_POLICIES
        | Self::MINISCRIPT_SEGWIT_V0
        | Self::MINISCRIPT_TAPROOT
        | Self::SILENT_PAYMENT_SENDS
        | Self::SILENT_PAYMENT_ACCOUNTS
        | Self::UNREGISTER_DESCRIPTOR
        | Self::MUSIG2
        | Self::NONCE_CACHE;

    pub fn supports(self, capability: Capability) -> bool {
        self.0 & capability.bit() != 0
    }

    pub fn supports_nonce_cache(self) -> bool {
        self.supports(Capability::NonceCache)
    }
}

/// A capability a signer can advertise in its `Capabilities` bitfield.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    Bip380Descriptors,
    Bip388WalletPolicies,
    MiniscriptSegwitV0,
    MiniscriptTaproot,
    SilentPaymentSends,
    SilentPaymentAccounts,
    UnregisterDescriptor,
    Musig2,
    NonceCache,
}

impl Capability {
    pub const ALL: [Self; 9] = [
        Self::Bip380Descriptors,
        Self::Bip388WalletPolicies,
        Self::MiniscriptSegwitV0,
        Self::MiniscriptTaproot,
        Self::SilentPaymentSends,
        Self::SilentPaymentAccounts,
        Self::UnregisterDescriptor,
        Self::Musig2,
        Self::NonceCache,
    ];

    pub const fn bit(self) -> u32 {
        match self {
            Self::Bip380Descriptors => Capabilities::BIP380_DESCRIPTORS,
            Self::Bip388WalletPolicies => Capabilities::BIP388_WALLET_POLICIES,
            Self::MiniscriptSegwitV0 => Capabilities::MINISCRIPT_SEGWIT_V0,
            Self::MiniscriptTaproot => Capabilities::MINISCRIPT_TAPROOT,
            Self::SilentPaymentSends => Capabilities::SILENT_PAYMENT_SENDS,
            Self::SilentPaymentAccounts => Capabilities::SILENT_PAYMENT_ACCOUNTS,
            Self::UnregisterDescriptor => Capabilities::UNREGISTER_DESCRIPTOR,
            Self::Musig2 => Capabilities::MUSIG2,
            Self::NonceCache => Capabilities::NONCE_CACHE,
        }
    }
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
    /// Present only when `state` is `State::Ready`.
    pub fingerprint: Option<Fingerprint>,
}

impl Info {
    pub fn validate(&self) -> Result<(), Invalid> {
        if usize::from(self.max_alias) > MAX_DESCRIPTOR_ALIAS {
            return Err(Invalid::MaxAliasTooLarge(self.max_alias));
        }
        if self.fingerprint.is_some() && self.state != State::Ready {
            return Err(Invalid::FingerprintWhenNotReady);
        }
        Ok(())
    }
}

wire_enum! {
    /// An unknown value counts as not ready.
    pub enum State {
        Ready = 0x00,
        Locked = 0x01,
        Uninitialized = 0x02,
        _ => Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Networks(pub u8);

impl Networks {
    pub const MAINNET: u8 = 1 << 1;
    pub const TESTNET: u8 = 1 << 2;
    pub const SIGNET: u8 = 1 << 3;
    pub const REGTEST: u8 = 1 << 4;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoncesPrepared {
    /// Present only when the signer initialized a new session for this answer.
    pub session: Option<Session>,
    /// The entry for key expression index `j` and input `i` is at
    /// `(j - start) * max_inputs + i`, with the request's `start` and `max_inputs`.
    pub nonces: Vec<[u8; MUSIG_PUB_NONCE_LEN]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    pub session_id: [u8; 4],
    pub session_ref: [u8; 4],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub descriptor_alias: String,
    pub registered: bool,
    pub stored: Option<bool>,
    pub proof: Option<Vec<u8>>,
}

/// The alias is no longer registered once the signer sends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unregistered {
    pub descriptor_alias: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressUri {
    pub uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signed {
    /// A serialized PSBT v0 or v2, carried without being parsed.
    Psbt(Vec<u8>),
    Signatures(Vec<SignatureEntry>),
}

wire_enum! {
    /// The `SIG_KIND` of a signature entry.
    pub enum SignatureKind {
        Ecdsa = 0x01,
        TapKey = 0x02,
        TapScript = 0x03,
        MusigPubNonce = 0x04,
        MusigPartialSig = 0x05,
        SpEcdhShare = 0x06,
        SpDleqProof = 0x07,
        _ => Unknown,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureEntry {
    Ecdsa {
        input_index: u32,
        public_key: PublicKey,
        signature: Vec<u8>,
    },
    TapKey {
        input_index: u32,
        signature: Vec<u8>,
    },
    TapScript {
        input_index: u32,
        xonly_public_key: [u8; 32],
        tap_leaf_hash: [u8; 32],
        signature: Vec<u8>,
    },
    MusigPubNonce {
        input_index: u32,
        participant: PublicKey,
        aggregate: PublicKey,
        leaf_hash: Option<[u8; 32]>,
        nonce: [u8; MUSIG_PUB_NONCE_LEN],
    },
    MusigPartialSig {
        input_index: u32,
        participant: PublicKey,
        aggregate: PublicKey,
        leaf_hash: Option<[u8; 32]>,
        signature: [u8; MUSIG_PARTIAL_SIG_LEN],
    },
    /// The value of BIP-375 `PSBT_GLOBAL_SP_ECDH_SHARE` or `PSBT_IN_SP_ECDH_SHARE`.
    SpEcdhShare {
        scope: SpScope,
        scan_key: PublicKey,
        share: PublicKey,
    },
    /// The value of BIP-375 `PSBT_GLOBAL_SP_DLEQ` or `PSBT_IN_SP_DLEQ`, a BIP-374 proof.
    SpDleqProof {
        scope: SpScope,
        scan_key: PublicKey,
        proof: [u8; DLEQ_PROOF_LEN],
    },
    /// An entry whose kind this codec does not know. It is kept rather than dropped so
    /// a consumer sees it and a relay re-encodes the message unchanged.
    Unknown {
        input_index: u32,
        kind: u8,
        fields: Vec<u8>,
    },
}

impl SignatureEntry {
    pub fn value(&self) -> u8 {
        match self {
            Self::Ecdsa { .. } => SignatureKind::Ecdsa.value(),
            Self::TapKey { .. } => SignatureKind::TapKey.value(),
            Self::TapScript { .. } => SignatureKind::TapScript.value(),
            Self::MusigPubNonce { .. } => SignatureKind::MusigPubNonce.value(),
            Self::MusigPartialSig { .. } => SignatureKind::MusigPartialSig.value(),
            Self::SpEcdhShare { .. } => SignatureKind::SpEcdhShare.value(),
            Self::SpDleqProof { .. } => SignatureKind::SpDleqProof.value(),
            Self::Unknown { kind, .. } => *kind,
        }
    }

    /// `None` for a global silent payment entry.
    pub fn input_index(&self) -> Option<u32> {
        match self {
            Self::Ecdsa { input_index, .. }
            | Self::TapKey { input_index, .. }
            | Self::TapScript { input_index, .. }
            | Self::MusigPubNonce { input_index, .. }
            | Self::MusigPartialSig { input_index, .. }
            | Self::Unknown { input_index, .. } => Some(*input_index),
            Self::SpEcdhShare { scope, .. } | Self::SpDleqProof { scope, .. } => {
                scope.input_index()
            }
        }
    }

    pub fn validate(&self) -> Result<(), Invalid> {
        match self {
            Self::Ecdsa { signature, .. } if signature.len() > ECDSA_SIGNATURE_MAX_LEN => {
                Err(Invalid::EcdsaSignatureLength(signature.len()))
            }
            Self::TapKey { signature, .. } | Self::TapScript { signature, .. }
                if !(SCHNORR_SIGNATURE_LEN..=SCHNORR_SIGNATURE_LEN + 1)
                    .contains(&signature.len()) =>
            {
                Err(Invalid::TaprootSignatureLength(signature.len()))
            }
            _ => Ok(()),
        }
    }
}

/// Whether a silent payment share or proof covers the whole transaction (the signer
/// owns every eligible input) or a single input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SpScope {
    Global,
    Input(u32),
}

impl SpScope {
    pub fn from_wire(global: bool, input_index: u32) -> Option<Self> {
        match (global, input_index) {
            (false, index) => Some(Self::Input(index)),
            (true, sp::GLOBAL_INPUT_INDEX) => Some(Self::Global),
            (true, _) => None,
        }
    }

    pub fn input_index(self) -> Option<u32> {
        match self {
            Self::Global => None,
            Self::Input(index) => Some(index),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorBody {
    pub message_type: MessageType,
    pub error: Error,
    pub message: String,
}

wire_enum! {
    pub enum Error {
        UserDeclined = 0x01,
        UnsupportedVersion = 0x02,
        MalformedRequest = 0x03,
        UnknownDescriptorAlias = 0x04,
        DescriptorRegistrationFailed = 0x05,
        UnsupportedDescriptorForm = 0x06,
        InvalidProof = 0x07,
        AddressMismatch = 0x08,
        NothingToSign = 0x09,
        InvalidPsbt = 0x0a,
        InternalError = 0x0b,
        MusigSession = 0x0c,
        AlreadyRegistered = 0x0d,
        UnsupportedOperation = 0x0e,
        NetworkMismatch = 0x0f,
        Vendor = 0xff,
        _ => Unknown,
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use crate::response::{Capabilities, FirmwareVersion, ReleaseFlag};

    #[test]
    fn version_and_capabilities_round_trip_through_serde() {
        let version = FirmwareVersion {
            major: 1,
            minor: 2,
            patch: 3,
            flag: ReleaseFlag::Unknown {
                channel: 9,
                number: 4,
            },
        };
        let json = serde_json::to_string(&version).unwrap();
        assert_eq!(
            serde_json::from_str::<FirmwareVersion>(&json).unwrap(),
            version
        );
        let capabilities = Capabilities(Capabilities::MUSIG2 | 1 << 31);
        let json = serde_json::to_string(&capabilities).unwrap();
        assert_eq!(
            serde_json::from_str::<Capabilities>(&json).unwrap(),
            capabilities
        );
    }
}
