#![cfg(all(feature = "coordinator", feature = "signer"))]

use core::fmt;

use bip377::{
    backend::Backend,
    ll::{
        self, RequestId,
        types::{
            DerivationPath, EXTENDED_KEY_LEN, ExtendedKey, Fingerprint, MUSIG_PARTIAL_SIG_LEN,
            PublicKey, SecretKey,
        },
    },
    request, response,
};

const ID: RequestId = RequestId([0, 7]);

#[derive(Debug, PartialEq)]
enum MockError {
    Encode(ll::encode::Error),
    Decode(ll::decode::Error),
    NotAResponse,
}

impl fmt::Display for MockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<ll::encode::Error> for MockError {
    fn from(error: ll::encode::Error) -> Self {
        Self::Encode(error)
    }
}

impl From<ll::decode::Error> for MockError {
    fn from(error: ll::decode::Error) -> Self {
        Self::Decode(error)
    }
}

impl From<response::NotAResponse> for MockError {
    fn from(_: response::NotAResponse) -> Self {
        Self::NotAResponse
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Mock {}

impl Backend for Mock {
    type DerivationPath = Vec<u32>;
    type Xpub = [u8; EXTENDED_KEY_LEN];
    type Fingerprint = [u8; 4];
    type PublicKey = [u8; 33];
    type SecretKey = [u8; 32];
    type Psbt = Vec<u8>;
    type Address = String;
    type EcdsaSignature = Vec<u8>;
    type TaprootSignature = Vec<u8>;
    type XOnlyPublicKey = [u8; 32];
    type TapLeafHash = [u8; 32];
    type MusigPartialSignature = [u8; MUSIG_PARTIAL_SIG_LEN];
    type Descriptor = String;
    type Request = request::Request<Self>;
    type Response = response::Response<Self>;
    type Error = MockError;

    fn encode_request(request: &request::Request<Self>) -> Result<Vec<u8>, MockError> {
        request::encode(request)
    }

    fn decode_response(bytes: &[u8]) -> Result<response::Response<Self>, MockError> {
        response::decode(bytes)
    }

    fn to_ll_path(path: &Vec<u32>) -> DerivationPath {
        DerivationPath(path.clone())
    }

    fn from_ll_path(path: &DerivationPath) -> Vec<u32> {
        path.0.clone()
    }

    fn to_ll_xpub(xpub: &[u8; EXTENDED_KEY_LEN]) -> ExtendedKey {
        ExtendedKey(*xpub)
    }

    fn from_ll_xpub(key: &ExtendedKey) -> Result<[u8; EXTENDED_KEY_LEN], MockError> {
        Ok(key.0)
    }

    fn to_ll_fingerprint(fingerprint: &[u8; 4]) -> Fingerprint {
        Fingerprint(*fingerprint)
    }

    fn from_ll_fingerprint(fingerprint: &Fingerprint) -> [u8; 4] {
        fingerprint.0
    }

    fn to_ll_public_key(key: &[u8; 33]) -> Result<PublicKey, MockError> {
        Ok(PublicKey(*key))
    }

    fn from_ll_public_key(key: &PublicKey) -> Result<[u8; 33], MockError> {
        Ok(key.0)
    }

    fn to_ll_secret_key(key: &[u8; 32]) -> SecretKey {
        SecretKey(*key)
    }

    fn from_ll_secret_key(key: &SecretKey) -> Result<[u8; 32], MockError> {
        Ok(key.0)
    }

    fn to_ll_psbt(psbt: &Vec<u8>) -> Vec<u8> {
        psbt.clone()
    }

    fn from_ll_psbt(psbt: &[u8]) -> Result<Vec<u8>, MockError> {
        Ok(psbt.to_vec())
    }

    fn to_ll_address(address: &String) -> String {
        address.clone()
    }

    fn from_ll_address_uri(uri: &str) -> Result<String, MockError> {
        Ok(uri.to_string())
    }

    fn to_ll_descriptor(descriptor: &String) -> String {
        descriptor.clone()
    }

    fn to_ll_xpub_string(xpub: &[u8; EXTENDED_KEY_LEN]) -> String {
        xpub.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn from_ll_ecdsa_signature(signature: &[u8]) -> Result<Vec<u8>, MockError> {
        Ok(signature.to_vec())
    }

    fn from_ll_taproot_signature(signature: &[u8]) -> Result<Vec<u8>, MockError> {
        Ok(signature.to_vec())
    }

    fn from_ll_xonly_public_key(key: &[u8; 32]) -> Result<[u8; 32], MockError> {
        Ok(*key)
    }

    fn from_ll_tap_leaf_hash(hash: &[u8; 32]) -> [u8; 32] {
        *hash
    }

    fn from_ll_musig_partial_signature(
        signature: &[u8; MUSIG_PARTIAL_SIG_LEN],
    ) -> Result<[u8; MUSIG_PARTIAL_SIG_LEN], MockError> {
        Ok(*signature)
    }
}

#[test]
fn a_typed_request_encodes_through_the_codec() {
    let bytes = Mock::encode_request(&request::Request {
        id: ID,
        body: request::Body::GetKeys(request::GetKeys {
            keys: vec![vec![0x8000_0054, 7]],
        }),
    })
    .unwrap();
    assert_eq!(
        ll::decode(&bytes).unwrap(),
        ll::Message::Request(ll::Request {
            id: ID,
            body: ll::request::Body::GetKeys(ll::request::GetKeys {
                keys: vec![DerivationPath(vec![0x8000_0054, 7])],
            }),
        })
    );
}

#[test]
fn a_typed_sign_response_decodes_through_the_codec() {
    let bytes = ll::encode_response(&ll::Response {
        id: ID,
        body: ll::response::Body::Signed(ll::response::Signed::Signatures(vec![
            ll::response::SignatureEntry::Ecdsa {
                input_index: 0,
                public_key: PublicKey([0x02; 33]),
                signature: vec![0x30; 71],
            },
            ll::response::SignatureEntry::TapScript {
                input_index: 1,
                xonly_public_key: [0x11; 32],
                tap_leaf_hash: [0x22; 32],
                signature: vec![0x33; 64],
            },
            ll::response::SignatureEntry::MusigPartialSig {
                input_index: 2,
                participant: PublicKey([0x03; 33]),
                aggregate: PublicKey([0x02; 33]),
                leaf_hash: None,
                signature: [0x44; MUSIG_PARTIAL_SIG_LEN],
            },
        ])),
    })
    .unwrap();
    assert_eq!(
        Mock::decode_response(&bytes).unwrap(),
        response::Response {
            id: ID,
            body: response::Body::Signed(response::Signed::Signatures(vec![
                response::SignatureEntry::Ecdsa {
                    input_index: 0,
                    public_key: [0x02; 33],
                    signature: vec![0x30; 71],
                },
                response::SignatureEntry::TapScript {
                    input_index: 1,
                    xonly_public_key: [0x11; 32],
                    tap_leaf_hash: [0x22; 32],
                    signature: vec![0x33; 64],
                },
                response::SignatureEntry::MusigPartialSig {
                    input_index: 2,
                    participant: [0x03; 33],
                    aggregate: [0x02; 33],
                    leaf_hash: None,
                    signature: [0x44; MUSIG_PARTIAL_SIG_LEN],
                },
            ])),
        }
    );
}

#[test]
fn a_request_is_not_a_response() {
    let bytes = ll::encode_request(&ll::Request {
        id: ID,
        body: ll::request::Body::GetInfo,
    })
    .unwrap();
    assert_eq!(Mock::decode_response(&bytes), Err(MockError::NotAResponse));
}
