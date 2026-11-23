#![cfg(all(feature = "bitcoin_0_32", feature = "coordinator", feature = "signer"))]

#[path = "../bip377-ll/tests/common/mod.rs"]
mod common;

use bip377::{
    backend::{
        Backend,
        rust_bitcoin::{Error, RustBitcoin},
    },
    bitcoin::{
        self, Amount, OutPoint, Psbt, ScriptBuf, Sequence, TapLeafHash, Transaction, TxIn, TxOut,
        Witness, XOnlyPublicKey,
        absolute::LockTime,
        address::NetworkUnchecked,
        bip32::{self, Xpub},
        ecdsa,
        hashes::Hash,
        secp256k1, taproot,
        transaction::Version,
    },
    ll::{self, MessageType, RequestId, SignResponseKind},
    request, response,
};
use bwk_address::{
    backend::rust_bitcoin::{Address, Error as AddressError, SilentPaymentAddress},
    uri::UriError,
};
use miniscript_12::{Descriptor, DescriptorPublicKey};

use common::{FOREIGN_SCAN_KEY, from_hex, sp_foreign_scan_keys, sp_keys, xpub};

const ID: RequestId = RequestId([0, 1]);
const XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
const ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const SP_ADDRESS: &str = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";
const ECDSA_SIGNATURE_HEX: &str = "3044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01";

fn descriptor_text() -> String {
    format!(
        "wsh(or_d(pk([3442193e/48'/1'/0'/2']{XPUB}/<0;1>/*),\
         and_v(v:pkh([3442193e/48'/1'/1'/2']{XPUB}/<2;3>/*),older(52560))))"
    )
}

fn descriptor() -> Descriptor<DescriptorPublicKey> {
    descriptor_text().parse().unwrap()
}

fn sp_address() -> SilentPaymentAddress {
    SilentPaymentAddress::try_from(SP_ADDRESS).unwrap()
}

fn bitcoin_xpub() -> Xpub {
    XPUB.parse().unwrap()
}

fn public_key() -> bitcoin::PublicKey {
    bitcoin::PublicKey::new(bitcoin_xpub().public_key)
}

fn ll_public_key() -> ll::types::PublicKey {
    ll::types::PublicKey(bitcoin_xpub().public_key.serialize())
}

fn address(text: &str) -> bitcoin::Address<NetworkUnchecked> {
    text.parse().unwrap()
}

fn path(text: &str) -> bip32::DerivationPath {
    text.parse().unwrap()
}

fn psbt() -> Psbt {
    Psbt::from_unsigned_tx(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new(),
        }],
    })
    .unwrap()
}

fn sent(body: request::Body<RustBitcoin>) -> ll::request::Body {
    let bytes = RustBitcoin::encode_request(&request::Request { id: ID, body }).unwrap();
    let ll::Message::Request(request) = ll::decode(&bytes).unwrap() else {
        panic!("not a request");
    };
    assert_eq!(request.id, ID);
    request.body
}

fn received(body: ll::response::Body) -> Result<response::Body<RustBitcoin>, Error> {
    let bytes = ll::encode_response(&ll::Response { id: ID, body }).unwrap();
    RustBitcoin::decode_response(&bytes).map(|response| {
        assert_eq!(response.id, ID);
        response.body
    })
}

fn signatures(entries: Vec<ll::response::SignatureEntry>) -> ll::response::Body {
    ll::response::Body::Signed(ll::response::Signed::Signatures(entries))
}

fn typed_signatures(
    entries: Vec<response::SignatureEntry<RustBitcoin>>,
) -> response::Body<RustBitcoin> {
    response::Body::Signed(response::Signed::Signatures(entries))
}

fn firmware_version() -> ll::response::FirmwareVersion {
    ll::response::FirmwareVersion {
        major: 1,
        minor: 2,
        patch: 3,
        flag: ll::response::ReleaseFlag::Stable,
    }
}

#[test]
fn get_info_request_encodes() {
    assert_eq!(sent(request::Body::GetInfo), ll::request::Body::GetInfo);
}

#[test]
fn get_keys_request_encodes() {
    assert_eq!(
        sent(request::Body::GetKeys(request::GetKeys {
            keys: vec![path("m/48'/0'/0'/2'"), path("m/84'/1'/0'")],
        })),
        ll::request::Body::GetKeys(ll::request::GetKeys {
            keys: vec![common::path("m/48'/0'/0'/2'"), common::path("m/84'/1'/0'"),],
        })
    );
}

#[test]
fn register_descriptor_request_encodes_every_descriptor_form() {
    let sp_spend_path = path("m/352'/1'/0'/0'/0");
    let sp_fingerprint = bip32::Fingerprint::from([0x73, 0xc5, 0xda, 0x0a]);
    for (descriptor, expected) in [
        (None, None),
        (
            Some(request::DescriptorBody::Bip380(descriptor())),
            Some(ll::request::DescriptorBody::Bip380(
                descriptor().to_string(),
            )),
        ),
        (
            Some(request::DescriptorBody::Bip388 {
                keys: vec![
                    request::KeyInfo {
                        origin: Some(request::KeyOrigin {
                            fingerprint: bip32::Fingerprint::from([0x34, 0x42, 0x19, 0x3e]),
                            path: path("m/48'/1'/0'/2'"),
                        }),
                        xpub: bitcoin_xpub(),
                    },
                    request::KeyInfo {
                        origin: Some(request::KeyOrigin {
                            fingerprint: bip32::Fingerprint::from([0x34, 0x42, 0x19, 0x3e]),
                            path: path("m"),
                        }),
                        xpub: bitcoin_xpub(),
                    },
                    request::KeyInfo {
                        origin: None,
                        xpub: bitcoin_xpub(),
                    },
                ],
                policy: "sh(multi(2,@0/**,@1/**,@2/**))".to_string(),
            }),
            Some(ll::request::DescriptorBody::Bip388 {
                keys: vec![
                    format!("[3442193e/48'/1'/0'/2']{XPUB}"),
                    format!("[3442193e]{XPUB}"),
                    XPUB.to_string(),
                ],
                policy: "sh(multi(2,@0/**,@1/**,@2/**))".to_string(),
            }),
        ),
        (
            Some(request::DescriptorBody::SpKeys(request::SpKeys {
                fingerprint: sp_fingerprint,
                spend_path: sp_spend_path.clone(),
                scan: request::Scan::Path(path("m/352'/1'/0'/1'/0")),
            })),
            Some(sp_keys()),
        ),
        (
            Some(request::DescriptorBody::SpKeys(request::SpKeys {
                fingerprint: sp_fingerprint,
                spend_path: sp_spend_path.clone(),
                scan: request::Scan::Key(
                    secp256k1::SecretKey::from_slice(&FOREIGN_SCAN_KEY).unwrap(),
                ),
            })),
            Some(sp_foreign_scan_keys()),
        ),
    ] {
        assert_eq!(
            sent(request::Body::RegisterDescriptor(
                request::RegisterDescriptor {
                    descriptor_alias: "main".to_string(),
                    descriptor,
                }
            )),
            ll::request::Body::RegisterDescriptor(ll::request::RegisterDescriptor {
                descriptor_alias: "main".to_string(),
                descriptor: expected,
            })
        );
    }
}

#[test]
fn a_bip380_descriptor_is_sent_as_its_string() {
    let body = sent(request::Body::RegisterDescriptor(
        request::RegisterDescriptor {
            descriptor_alias: "main".to_string(),
            descriptor: Some(request::DescriptorBody::Bip380(descriptor())),
        },
    ));
    let ll::request::Body::RegisterDescriptor(ll::request::RegisterDescriptor {
        descriptor: Some(ll::request::DescriptorBody::Bip380(wire)),
        ..
    }) = body
    else {
        panic!("not a BIP-380 registration: {body:?}");
    };
    let (text, checksum) = wire.split_once('#').unwrap();
    assert_eq!(text, descriptor_text());
    assert_eq!(checksum.len(), 8);
    assert_eq!(
        wire.parse::<Descriptor<DescriptorPublicKey>>().unwrap(),
        descriptor()
    );
}

#[test]
fn verify_address_request_encodes_each_address_kind() {
    for (address, expected) in [
        (None, None),
        (
            Some(Address::Bitcoin(address(ADDRESS))),
            Some(ADDRESS.to_string()),
        ),
        (
            Some(Address::SilentPayment(sp_address())),
            Some(SP_ADDRESS.to_string()),
        ),
    ] {
        assert_eq!(
            sent(request::Body::VerifyAddress(request::VerifyAddress {
                descriptor_alias: "main".to_string(),
                derivation_path: path("m/0/7"),
                address,
                descriptor: None,
                proof: Some(vec![0xaa; 32]),
            })),
            ll::request::Body::VerifyAddress(ll::request::VerifyAddress {
                descriptor_alias: "main".to_string(),
                derivation_path: common::path("m/0/7"),
                address: expected,
                descriptor: None,
                proof: Some(vec![0xaa; 32]),
            })
        );
    }
}

#[test]
fn sign_request_encodes() {
    assert_eq!(
        sent(request::Body::Sign(request::Sign {
            descriptors: vec![request::Descriptor {
                alias: "main".to_string(),
                descriptor: None,
                proof: None,
            }],
            psbt: psbt(),
            want_kind: Some(SignResponseKind::Signatures),
            accept_trimmed: true,
        })),
        ll::request::Body::Sign(ll::request::Sign {
            descriptors: vec![ll::request::Descriptor {
                alias: "main".to_string(),
                descriptor: None,
                proof: None,
            }],
            psbt: psbt().serialize(),
            want_kind: Some(SignResponseKind::Signatures),
            accept_trimmed: true,
        })
    );
}

#[test]
fn prepare_nonces_request_encodes() {
    assert_eq!(
        sent(request::Body::PrepareNonces(request::PrepareNonces {
            session_id: Some([1, 2, 3, 4]),
            session_ref: Some([5, 6, 7, 8]),
            descriptor: Some(request::Descriptor {
                alias: "main".to_string(),
                descriptor: Some(request::DescriptorBody::Bip380(descriptor())),
                proof: None,
            }),
            max_inputs: 2,
            derivation_path: path("m/0/7"),
            start: 0,
            end: Some(1),
        })),
        ll::request::Body::PrepareNonces(ll::request::PrepareNonces {
            session_id: Some([1, 2, 3, 4]),
            session_ref: Some([5, 6, 7, 8]),
            descriptor: Some(ll::request::Descriptor {
                alias: "main".to_string(),
                descriptor: Some(ll::request::DescriptorBody::Bip380(
                    descriptor().to_string()
                )),
                proof: None,
            }),
            max_inputs: 2,
            derivation_path: common::path("m/0/7"),
            start: 0,
            end: Some(1),
        })
    );
}

#[test]
fn unregister_descriptor_request_encodes() {
    let unregister = ll::request::UnregisterDescriptor {
        descriptor_alias: "main".to_string(),
    };
    assert_eq!(
        sent(request::Body::UnregisterDescriptor(unregister.clone())),
        ll::request::Body::UnregisterDescriptor(unregister)
    );
}

#[test]
fn encode_request_reports_the_codec_error() {
    let body = request::Body::PrepareNonces(request::PrepareNonces {
        session_id: None,
        session_ref: None,
        descriptor: None,
        max_inputs: 0,
        derivation_path: path("m/0/7"),
        start: 0,
        end: None,
    });
    assert!(matches!(
        RustBitcoin::encode_request(&request::Request { id: ID, body }),
        Err(Error::Encode(ll::encode::Error::Invalid(
            ll::Invalid::ZeroMaxInputs
        )))
    ));
}

#[test]
fn info_response_decodes() {
    let body = received(ll::response::Body::Info(ll::response::Info {
        vendor: "bip".to_string(),
        model: "bip-signer".to_string(),
        version: firmware_version(),
        capabilities: ll::response::Capabilities(0),
        state: ll::response::State::Ready,
        networks: ll::response::Networks(ll::response::Networks::SIGNET),
        max_message: 1024,
        max_alias: 32,
        fingerprint: Some(ll::types::Fingerprint([0x34, 0x42, 0x19, 0x3e])),
    }));
    assert_eq!(
        body.unwrap(),
        response::Body::Info(response::Info {
            vendor: "bip".to_string(),
            model: "bip-signer".to_string(),
            version: firmware_version(),
            capabilities: ll::response::Capabilities(0),
            state: ll::response::State::Ready,
            networks: ll::response::Networks(ll::response::Networks::SIGNET),
            max_message: 1024,
            max_alias: 32,
            fingerprint: Some(bitcoin_xpub().fingerprint()),
        })
    );
}

#[test]
fn keys_response_decodes() {
    let body = received(ll::response::Body::Keys(ll::response::Keys {
        keys: vec![xpub()],
        fingerprint: ll::types::Fingerprint([0x34, 0x42, 0x19, 0x3e]),
        vendor: "bip".to_string(),
        model: "bip-signer".to_string(),
        version: firmware_version(),
        capabilities: ll::response::Capabilities(ll::response::Capabilities::MUSIG2),
    }));
    assert_eq!(
        body.unwrap(),
        response::Body::Keys(response::Keys {
            keys: vec![bitcoin_xpub()],
            fingerprint: bitcoin_xpub().fingerprint(),
            vendor: "bip".to_string(),
            model: "bip-signer".to_string(),
            version: firmware_version(),
            capabilities: ll::response::Capabilities(ll::response::Capabilities::MUSIG2),
        })
    );
}

#[test]
fn keys_response_with_an_invalid_xpub_is_refused() {
    let mut key = xpub();
    key.0[45] = 0x05;
    let body = received(ll::response::Body::Keys(ll::response::Keys {
        keys: vec![key],
        fingerprint: ll::types::Fingerprint([0; 4]),
        vendor: "bip".to_string(),
        model: "bip-signer".to_string(),
        version: firmware_version(),
        capabilities: ll::response::Capabilities(0),
    }));
    assert!(matches!(body, Err(Error::ExtendedKey(_))));
}

#[test]
fn plain_responses_decode_unchanged() {
    let registration = ll::response::Registration {
        descriptor_alias: "main".to_string(),
        registered: true,
        stored: Some(false),
        proof: Some(vec![0xaa; 32]),
    };
    let nonces = ll::response::NoncesPrepared {
        session: Some(ll::response::Session {
            session_id: [1, 2, 3, 4],
            session_ref: [5, 6, 7, 8],
        }),
        nonces: vec![[0x22; 66]],
    };
    let unregistered = ll::response::Unregistered {
        descriptor_alias: "main".to_string(),
    };
    let error = ll::response::ErrorBody {
        message_type: MessageType::Signing,
        error: ll::response::Error::UserDeclined,
        message: "declined".to_string(),
    };
    assert_eq!(
        received(ll::response::Body::Registration(registration.clone())).unwrap(),
        response::Body::Registration(registration)
    );
    assert_eq!(
        received(ll::response::Body::NoncesPrepared(nonces.clone())).unwrap(),
        response::Body::NoncesPrepared(nonces)
    );
    assert_eq!(
        received(ll::response::Body::Unregistered(unregistered.clone())).unwrap(),
        response::Body::Unregistered(unregistered)
    );
    assert_eq!(
        received(ll::response::Body::Error(error.clone())).unwrap(),
        response::Body::Error(error)
    );
}

fn received_uri(uri: &str) -> Result<response::Body<RustBitcoin>, Error> {
    received(ll::response::Body::AddressUri(ll::response::AddressUri {
        uri: uri.to_string(),
    }))
}

#[test]
fn a_bitcoin_address_uri_decodes() {
    assert_eq!(
        received_uri(&format!("bitcoin:{ADDRESS}?label=main")).unwrap(),
        response::Body::Address(Address::Bitcoin(address(ADDRESS)))
    );
}

#[test]
fn a_silent_payment_uri_decodes() {
    assert_eq!(
        received_uri(&format!("bitcoin:?sp={SP_ADDRESS}")).unwrap(),
        response::Body::Address(Address::SilentPayment(sp_address()))
    );
}

#[test]
fn a_refused_uri_is_an_address_uri_error() {
    for (uri, expected) in [
        ("litecoin:x".to_string(), UriError::InvalidScheme),
        ("bitcoin:".to_string(), UriError::NoAddress),
        (
            format!("bitcoin:{ADDRESS}?sp={SP_ADDRESS}"),
            UriError::MultipleAddresses,
        ),
    ] {
        match received_uri(&uri) {
            Err(Error::AddressUri(error)) => {
                assert_eq!(error, AddressError::Uri(expected), "{uri}")
            }
            other => panic!("{uri}: {other:?}"),
        }
    }
}

#[test]
fn an_invalid_bitcoin_address_is_an_address_uri_error() {
    assert!(matches!(
        received_uri("bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"),
        Err(Error::AddressUri(AddressError::Address(_)))
    ));
}

#[test]
fn an_invalid_silent_payment_address_is_an_address_uri_error() {
    assert!(matches!(
        received_uri("bitcoin:?sp=sp1qqqqqqqqq"),
        Err(Error::AddressUri(AddressError::SilentPaymentAddress(_)))
    ));
}

#[test]
fn signed_psbt_response_decodes() {
    let body = received(ll::response::Body::Signed(ll::response::Signed::Psbt(
        psbt().serialize(),
    )));
    assert_eq!(
        body.unwrap(),
        response::Body::Signed(response::Signed::Psbt(psbt()))
    );
}

#[test]
fn an_invalid_psbt_is_refused() {
    let body = received(ll::response::Body::Signed(ll::response::Signed::Psbt(
        vec![0x70, 0x73, 0x62, 0x74],
    )));
    assert!(matches!(body, Err(Error::Psbt(_))));
}

#[test]
fn every_signature_entry_decodes() {
    let ecdsa_signature = from_hex(ECDSA_SIGNATURE_HEX);
    let xonly = bitcoin_xpub().public_key.x_only_public_key().0;
    let entries = vec![
        ll::response::SignatureEntry::Ecdsa {
            input_index: 0,
            public_key: ll_public_key(),
            signature: ecdsa_signature.clone(),
        },
        ll::response::SignatureEntry::TapKey {
            input_index: 1,
            signature: vec![0x01; 64],
        },
        ll::response::SignatureEntry::TapScript {
            input_index: 2,
            xonly_public_key: xonly.serialize(),
            tap_leaf_hash: [0x44; 32],
            signature: [vec![0x02; 64], vec![0x83]].concat(),
        },
        ll::response::SignatureEntry::MusigPubNonce {
            input_index: 3,
            participant: ll_public_key(),
            aggregate: ll_public_key(),
            leaf_hash: Some([0x44; 32]),
            nonce: [0x22; 66],
        },
        ll::response::SignatureEntry::MusigPartialSig {
            input_index: 4,
            participant: ll_public_key(),
            aggregate: ll_public_key(),
            leaf_hash: None,
            signature: [0x66; 32],
        },
        ll::response::SignatureEntry::SpEcdhShare {
            scope: ll::response::SpScope::Global,
            scan_key: ll_public_key(),
            share: ll_public_key(),
        },
        ll::response::SignatureEntry::SpDleqProof {
            scope: ll::response::SpScope::Global,
            scan_key: ll_public_key(),
            proof: [0xb0; 64],
        },
        ll::response::SignatureEntry::Unknown {
            input_index: 5,
            kind: 0x20,
            fields: vec![0xde, 0xad],
        },
    ];
    let leaf_hash = TapLeafHash::from_byte_array([0x44; 32]);
    assert_eq!(
        received(signatures(entries)).unwrap(),
        typed_signatures(vec![
            response::SignatureEntry::Ecdsa {
                input_index: 0,
                public_key: public_key(),
                signature: ecdsa::Signature::from_slice(&ecdsa_signature).unwrap(),
            },
            response::SignatureEntry::TapKey {
                input_index: 1,
                signature: taproot::Signature::from_slice(&[0x01; 64]).unwrap(),
            },
            response::SignatureEntry::TapScript {
                input_index: 2,
                xonly_public_key: XOnlyPublicKey::from_slice(&xonly.serialize()).unwrap(),
                tap_leaf_hash: leaf_hash,
                signature: taproot::Signature::from_slice(&[vec![0x02; 64], vec![0x83]].concat())
                    .unwrap(),
            },
            response::SignatureEntry::MusigPubNonce {
                input_index: 3,
                participant: public_key(),
                aggregate: public_key(),
                leaf_hash: Some(leaf_hash),
                nonce: [0x22; 66],
            },
            response::SignatureEntry::MusigPartialSig {
                input_index: 4,
                participant: public_key(),
                aggregate: public_key(),
                leaf_hash: None,
                signature: secp256k1::Scalar::from_be_bytes([0x66; 32]).unwrap(),
            },
            response::SignatureEntry::SpEcdhShare {
                scope: ll::response::SpScope::Global,
                scan_key: public_key(),
                share: public_key(),
            },
            response::SignatureEntry::SpDleqProof {
                scope: ll::response::SpScope::Global,
                scan_key: public_key(),
                proof: [0xb0; 64],
            },
            response::SignatureEntry::Unknown {
                input_index: 5,
                kind: 0x20,
                fields: vec![0xde, 0xad],
            },
        ])
    );
}

#[test]
fn a_musig_partial_signature_out_of_range_is_refused() {
    let body = received(signatures(vec![
        ll::response::SignatureEntry::MusigPartialSig {
            input_index: 0,
            participant: ll_public_key(),
            aggregate: ll_public_key(),
            leaf_hash: None,
            signature: [0xff; 32],
        },
    ]));
    assert!(matches!(body, Err(Error::MusigPartialSignature(_))));
}

#[test]
fn an_invalid_ecdsa_signature_is_refused() {
    let body = received(signatures(vec![ll::response::SignatureEntry::Ecdsa {
        input_index: 0,
        public_key: ll_public_key(),
        signature: vec![0x30; 71],
    }]));
    assert!(matches!(body, Err(Error::EcdsaSignature(_))));
}

#[test]
fn a_taproot_signature_with_an_invalid_sighash_is_refused() {
    let body = received(signatures(vec![ll::response::SignatureEntry::TapKey {
        input_index: 0,
        signature: [vec![0x01; 64], vec![0x04]].concat(),
    }]));
    assert!(matches!(body, Err(Error::TaprootSignature(_))));
}

#[test]
fn an_xonly_key_off_the_curve_is_refused() {
    let body = received(signatures(vec![ll::response::SignatureEntry::TapScript {
        input_index: 0,
        xonly_public_key: [0xff; 32],
        tap_leaf_hash: [0x44; 32],
        signature: vec![0x01; 64],
    }]));
    assert!(matches!(body, Err(Error::XOnlyPublicKey(_))));
}

#[test]
fn a_public_key_off_the_curve_is_refused() {
    let body = received(signatures(vec![ll::response::SignatureEntry::Ecdsa {
        input_index: 0,
        public_key: ll::types::PublicKey([0x05; 33]),
        signature: from_hex(ECDSA_SIGNATURE_HEX),
    }]));
    assert!(matches!(body, Err(Error::PublicKey(_))));
}

#[test]
fn decode_response_refuses_a_request() {
    let bytes = ll::encode_request(&ll::Request {
        id: ID,
        body: ll::request::Body::GetInfo,
    })
    .unwrap();
    assert!(matches!(
        RustBitcoin::decode_response(&bytes),
        Err(Error::NotAResponse)
    ));
}

#[test]
fn decode_response_reports_the_codec_error() {
    assert!(matches!(
        RustBitcoin::decode_response(b"BIP000"),
        Err(Error::Decode(ll::decode::Error::InvalidMagic))
    ));
}
