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
};

const ID: RequestId = RequestId([0, 7]);

#[derive(Debug)]
struct MockError(&'static str);

impl fmt::Display for MockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

#[derive(Debug, PartialEq)]
enum MockRequest {
    GetKeys(Vec<Vec<u32>>),
}

#[derive(Debug, PartialEq)]
enum MockResponse {
    Keys(Vec<[u8; EXTENDED_KEY_LEN]>),
}

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
    type Request = MockRequest;
    type Response = MockResponse;
    type Error = MockError;

    fn encode_request(request: &MockRequest) -> Result<Vec<u8>, MockError> {
        let body = match request {
            MockRequest::GetKeys(paths) => ll::request::Body::GetKeys(ll::request::GetKeys {
                keys: paths.iter().map(Self::to_ll_path).collect(),
            }),
        };
        ll::encode_request(&ll::Request { id: ID, body }).map_err(|_| MockError("encode"))
    }

    fn decode_response(bytes: &[u8]) -> Result<MockResponse, MockError> {
        match ll::decode(bytes).map_err(|_| MockError("decode"))? {
            ll::Message::Response(ll::Response {
                body: ll::response::Body::Keys(keys),
                ..
            }) => Ok(MockResponse::Keys(
                keys.keys.iter().map(|key| key.0).collect(),
            )),
            _ => Err(MockError("not a keys response")),
        }
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

    fn to_ll_descriptor(descriptor: &String) -> String {
        descriptor.clone()
    }

    fn from_ll_address(address: &str) -> Result<String, MockError> {
        Ok(address.to_string())
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
fn a_consumer_request_encodes_through_the_codec() {
    let bytes = Mock::encode_request(&MockRequest::GetKeys(vec![vec![0x8000_0054, 7]])).unwrap();
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
fn a_consumer_response_decodes_through_the_codec() {
    let bytes = ll::encode_response(&ll::Response {
        id: ID,
        body: ll::response::Body::Keys(ll::response::Keys {
            keys: vec![ExtendedKey([0x11; EXTENDED_KEY_LEN])],
            fingerprint: Fingerprint([1, 2, 3, 4]),
            vendor: "mock".to_string(),
            model: "signer".to_string(),
            version: ll::response::FirmwareVersion {
                major: 1,
                minor: 0,
                patch: 0,
                flag: ll::response::ReleaseFlag::Stable,
            },
            capabilities: ll::response::Capabilities(0),
        }),
    })
    .unwrap();
    assert_eq!(
        Mock::decode_response(&bytes).unwrap(),
        MockResponse::Keys(vec![[0x11; EXTENDED_KEY_LEN]])
    );
}
