use alloc::{string::String, vec::Vec};

use crate::{
    DIRECTION_RESPONSE, ErrorInfo, Invalid, MAGIC, MAX_DESCRIPTOR_ALIAS, Message, MessageType,
    Request, RequestId, Response, STATUS_ERROR, SignResponseKind, TYPE_MASK,
    reader::{self, Reader},
    request, response, sp,
    types::{DerivationPath, ExtendedKey, Fingerprint, PublicKey, SecretKey},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidMagic,
    ReservedVersion,
    UnknownMessageType(u8),
    ErrorStatusOnRequest,
    UnknownDescriptorForm(u8),
    UnknownSignResponseKind(u8),
    SignatureLength(u8),
    GlobalInputIndex(u32),
    ScanPathAndKey,
    NoScan,
    UnpairedSession,
    UnreadableRequestType,
    Invalid(Invalid),
    Read(reader::Error),
}

impl Error {
    pub fn info(&self) -> ErrorInfo {
        match self {
            Self::InvalidMagic => error_info!(200, "invalid magic"),
            Self::ReservedVersion => error_info!(201, "reserved protocol version"),
            Self::UnknownMessageType(_) => error_info!(202, "unknown message type"),
            Self::ErrorStatusOnRequest => error_info!(203, "request cannot carry error status"),
            Self::UnknownDescriptorForm(_) => error_info!(204, "unknown descriptor form"),
            Self::UnknownSignResponseKind(_) => error_info!(206, "unknown signing response kind"),
            Self::SignatureLength(_) => {
                error_info!(208, "signature entry fields do not fill its length")
            }
            Self::GlobalInputIndex(_) => {
                error_info!(209, "global silent payment entry has a nonzero input index")
            }
            Self::ScanPathAndKey => {
                error_info!(
                    210,
                    "silent payment keys carry both a scan path and a scan key"
                )
            }
            Self::NoScan => {
                error_info!(
                    211,
                    "silent payment keys carry neither a scan path nor a scan key"
                )
            }
            Self::UnpairedSession => {
                error_info!(
                    212,
                    "nonce preparation response carries only one of session id and ref"
                )
            }
            Self::UnreadableRequestType => {
                error_info!(213, "unreadable request type outside an error response")
            }
            Self::Invalid(error) => error.info(),
            Self::Read(inner) => inner.info(),
        }
    }
}

error_display!(Error);

impl From<Invalid> for Error {
    fn from(error: Invalid) -> Self {
        Self::Invalid(error)
    }
}

impl From<reader::Error> for Error {
    fn from(error: reader::Error) -> Self {
        Self::Read(error)
    }
}

pub fn decode(bytes: &[u8]) -> Result<Message, Error> {
    let mut reader = Reader::new(bytes);
    read_magic(&mut reader)?;
    // The minimum version is 1.
    if reader.take_u8()? == 0 {
        return Err(Error::ReservedVersion);
    }
    let msg_type = reader.take_u8()?;
    let response = msg_type & DIRECTION_RESPONSE != 0;
    let error = msg_type & STATUS_ERROR != 0;
    let message_type = MessageType::try_from(msg_type & TYPE_MASK)?;
    if error && !response {
        return Err(Error::ErrorStatusOnRequest);
    }
    let id = RequestId(reader.take_array()?);
    if response {
        decode_response(&mut reader, id, error, message_type).map(Message::Response)
    } else {
        decode_request(&mut reader, id, message_type).map(Message::Request)
    }
}

fn decode_request(
    reader: &mut Reader<'_>,
    id: RequestId,
    message_type: MessageType,
) -> Result<Request, Error> {
    let body = match message_type {
        MessageType::UnreadableRequest => return Err(Error::UnreadableRequestType),
        MessageType::GetInfo => request::Body::GetInfo,
        MessageType::GetKeys => request::Body::GetKeys(read_get_keys_request(reader)?),
        MessageType::RegisterDescriptor => {
            request::Body::RegisterDescriptor(read_register_request(reader)?)
        }
        MessageType::AddressVerification => {
            request::Body::VerifyAddress(read_verify_address_request(reader)?)
        }
        MessageType::Signing => request::Body::Sign(read_sign_request(reader)?),
        MessageType::NoncePreparation => request::Body::PrepareNonces(read_prepare_nonces(reader)?),
        MessageType::UnregisterDescriptor => {
            request::Body::UnregisterDescriptor(read_unregister_request(reader)?)
        }
    };
    Ok(Request { id, body })
}

fn decode_response(
    reader: &mut Reader<'_>,
    id: RequestId,
    error: bool,
    message_type: MessageType,
) -> Result<Response, Error> {
    if error {
        let response = Response {
            id,
            body: response::Body::Error(read_error_response(reader, message_type)?),
        };
        response.validate()?;
        return Ok(response);
    }
    let body = match message_type {
        MessageType::UnreadableRequest => return Err(Error::UnreadableRequestType),
        MessageType::GetInfo => response::Body::Info(read_info_response(reader)?),
        MessageType::GetKeys => response::Body::Keys(read_keys_response(reader)?),
        MessageType::RegisterDescriptor => {
            response::Body::Registration(read_registration_response(reader)?)
        }
        MessageType::AddressVerification => {
            response::Body::AddressUri(read_address_response(reader)?)
        }
        MessageType::Signing => response::Body::Signed(read_signed_response(reader)?),
        MessageType::NoncePreparation => {
            response::Body::NoncesPrepared(read_nonces_prepared(reader)?)
        }
        MessageType::UnregisterDescriptor => {
            response::Body::Unregistered(read_unregistered_response(reader)?)
        }
    };
    Ok(Response { id, body })
}

fn read_magic(reader: &mut Reader<'_>) -> Result<(), Error> {
    if reader.take_slice(MAGIC.len())? != MAGIC {
        return Err(Error::InvalidMagic);
    }
    Ok(())
}

fn read_get_keys_request(reader: &mut Reader<'_>) -> Result<request::GetKeys, Error> {
    Ok(request::GetKeys {
        keys: reader.take_vec(read_path)?,
    })
}

fn read_register_request(reader: &mut Reader<'_>) -> Result<request::RegisterDescriptor, Error> {
    let descriptor_alias = read_descriptor_alias(reader)?;
    let descriptor = reader.take_option(read_descriptor_body)?;
    Ok(request::RegisterDescriptor {
        descriptor_alias,
        descriptor,
    })
}

fn read_unregister_request(
    reader: &mut Reader<'_>,
) -> Result<request::UnregisterDescriptor, Error> {
    Ok(request::UnregisterDescriptor {
        descriptor_alias: read_descriptor_alias(reader)?,
    })
}

fn read_verify_address_request(reader: &mut Reader<'_>) -> Result<request::VerifyAddress, Error> {
    let descriptor_alias = read_descriptor_alias(reader)?;
    let derivation_path = read_path(reader)?;
    let address = reader.take_option(Reader::take_string)?;
    let descriptor = reader.take_option(read_descriptor_body)?;
    let proof = reader.take_option(Reader::take_bytes)?;
    Ok(request::VerifyAddress {
        descriptor_alias,
        derivation_path,
        address,
        descriptor,
        proof,
    })
}

fn read_sign_request(reader: &mut Reader<'_>) -> Result<request::Sign, Error> {
    let descriptors = reader.take_vec(read_descriptor)?;
    let psbt = reader.take_bytes()?;
    let want_kind = reader.take_option(read_want_kind)?.flatten();
    let accept_trimmed = reader.take_bool()?;
    Ok(request::Sign {
        descriptors,
        psbt,
        want_kind,
        accept_trimmed,
    })
}

fn read_prepare_nonces(reader: &mut Reader<'_>) -> Result<request::PrepareNonces, Error> {
    let session_id = reader.take_option(|r| r.take_array())?;
    let session_ref = reader.take_option(|r| r.take_array())?;
    let descriptor = reader.take_option(read_descriptor)?;
    let max_inputs = reader.take_u32_be()?;
    let derivation_path = read_path(reader)?;
    let start = reader.take_u32_be()?;
    let end = reader.take_option(|r| r.take_u32_be())?;
    let request = request::PrepareNonces {
        session_id,
        session_ref,
        descriptor,
        max_inputs,
        derivation_path,
        start,
        end,
    };
    request.validate()?;
    Ok(request)
}

fn read_nonces_prepared(reader: &mut Reader<'_>) -> Result<response::NoncesPrepared, Error> {
    let session_id = reader.take_option(|r| r.take_array())?;
    let session_ref = reader.take_option(|r| r.take_array())?;
    let session = match (session_id, session_ref) {
        (Some(session_id), Some(session_ref)) => Some(response::Session {
            session_id,
            session_ref,
        }),
        (None, None) => None,
        _ => return Err(Error::UnpairedSession),
    };
    Ok(response::NoncesPrepared {
        session,
        nonces: reader.take_vec(|r| r.take_array())?,
    })
}

fn read_keys_response(reader: &mut Reader<'_>) -> Result<response::Keys, Error> {
    let keys = reader.take_vec(read_extended_key)?;
    let fingerprint = read_fingerprint(reader)?;
    let vendor = reader.take_string()?;
    let model = reader.take_string()?;
    let version = read_version(reader)?;
    let capabilities = read_capabilites(reader)?;
    Ok(response::Keys {
        keys,
        fingerprint,
        vendor,
        model,
        version,
        capabilities,
    })
}

fn read_info_response(reader: &mut Reader<'_>) -> Result<response::Info, Error> {
    let vendor = reader.take_string()?;
    let model = reader.take_string()?;
    let version = read_version(reader)?;
    let capabilities = read_capabilites(reader)?;
    let state = reader.take_u8()?.into();
    let networks = response::Networks(reader.take_u8()?);
    let max_message = reader.take_u32_be()?;
    let max_alias = reader.take_u8()?;
    let fingerprint = reader.take_option(read_fingerprint)?;
    let response = response::Info {
        vendor,
        model,
        version,
        capabilities,
        state,
        networks,
        max_message,
        max_alias,
        fingerprint,
    };
    response.validate()?;
    Ok(response)
}

fn read_registration_response(reader: &mut Reader<'_>) -> Result<response::Registration, Error> {
    let descriptor_alias = read_descriptor_alias(reader)?;
    let registered = reader.take_bool()?;
    let stored = reader.take_option(Reader::take_bool)?;
    let proof = reader.take_option(Reader::take_bytes)?;
    Ok(response::Registration {
        descriptor_alias,
        registered,
        stored,
        proof,
    })
}

fn read_unregistered_response(reader: &mut Reader<'_>) -> Result<response::Unregistered, Error> {
    Ok(response::Unregistered {
        descriptor_alias: read_descriptor_alias(reader)?,
    })
}

fn read_address_response(reader: &mut Reader<'_>) -> Result<response::AddressUri, Error> {
    Ok(response::AddressUri {
        uri: reader.take_string()?,
    })
}

fn read_signed_response(reader: &mut Reader<'_>) -> Result<response::Signed, Error> {
    match read_sign_response_kind(reader)? {
        SignResponseKind::Psbt => Ok(response::Signed::Psbt(reader.take_bytes()?)),
        SignResponseKind::Signatures => {
            let entries = reader.take_vec(read_signature)?;
            sp::validate_entries(&entries)?;
            Ok(response::Signed::Signatures(entries))
        }
    }
}

fn read_error_response(
    reader: &mut Reader<'_>,
    message_type: MessageType,
) -> Result<response::ErrorBody, Error> {
    let error = reader.take_u8()?.into();
    let message = reader.take_string()?;
    Ok(response::ErrorBody {
        message_type,
        error,
        message,
    })
}

fn read_descriptor(reader: &mut Reader<'_>) -> Result<request::Descriptor, Error> {
    let alias = read_descriptor_alias(reader)?;
    let descriptor = reader.take_option(read_descriptor_body)?;
    let proof = reader.take_option(Reader::take_bytes)?;
    Ok(request::Descriptor {
        alias,
        descriptor,
        proof,
    })
}

fn read_descriptor_body(reader: &mut Reader<'_>) -> Result<request::DescriptorBody, Error> {
    match request::DescriptorForm::try_from(reader.take_u8()?)? {
        request::DescriptorForm::Bip380 => {
            Ok(request::DescriptorBody::Bip380(reader.take_string()?))
        }
        request::DescriptorForm::Bip388 => {
            let keys = reader.take_vec(Reader::take_string)?;
            let policy = reader.take_string()?;
            Ok(request::DescriptorBody::Bip388 { keys, policy })
        }
        request::DescriptorForm::SpKeys => {
            Ok(request::DescriptorBody::SpKeys(read_sp_keys(reader)?))
        }
    }
}

fn read_sp_keys(reader: &mut Reader<'_>) -> Result<request::SpKeys, Error> {
    let fingerprint = read_fingerprint(reader)?;
    let spend_path = read_path(reader)?;
    let scan = read_scan(reader)?;
    Ok(request::SpKeys {
        fingerprint,
        spend_path,
        scan,
    })
}

fn read_scan(reader: &mut Reader<'_>) -> Result<request::Scan, Error> {
    let path = reader.take_option(read_path)?;
    let key = reader.take_option(read_secret_key)?;
    match (path, key) {
        (Some(path), None) => Ok(request::Scan::Path(path)),
        (None, Some(key)) => Ok(request::Scan::Key(key)),
        (Some(_), Some(_)) => Err(Error::ScanPathAndKey),
        (None, None) => Err(Error::NoScan),
    }
}

fn read_signature(reader: &mut Reader<'_>) -> Result<response::SignatureEntry, Error> {
    let input_index = reader.take_u32_be()?;
    let kind = reader.take_u8()?;
    let mut fields = Reader::new(reader.take_bytes_slice()?);
    // running out of bytes inside the fields means they overflow the entry's LENGTH
    let entry =
        read_signature_fields(&mut fields, input_index, kind).map_err(|error| match error {
            Error::Read(reader::Error::Truncated) => Error::SignatureLength(kind),
            error => error,
        })?;
    if !fields.is_empty() {
        return Err(Error::SignatureLength(kind));
    }
    entry.validate()?;
    Ok(entry)
}

fn read_signature_fields(
    reader: &mut Reader<'_>,
    input_index: u32,
    kind: u8,
) -> Result<response::SignatureEntry, Error> {
    match response::SignatureKind::from(kind) {
        response::SignatureKind::Ecdsa => {
            let public_key = read_pubkey(reader)?;
            let signature = reader.take_bytes()?;
            Ok(response::SignatureEntry::Ecdsa {
                input_index,
                public_key,
                signature,
            })
        }
        response::SignatureKind::TapKey => Ok(response::SignatureEntry::TapKey {
            input_index,
            signature: reader.take_bytes()?,
        }),
        response::SignatureKind::TapScript => {
            let xonly_public_key = reader.take_array()?;
            let tap_leaf_hash = reader.take_array()?;
            let signature = reader.take_bytes()?;
            Ok(response::SignatureEntry::TapScript {
                input_index,
                xonly_public_key,
                tap_leaf_hash,
                signature,
            })
        }
        response::SignatureKind::MusigPubNonce => {
            let participant = read_pubkey(reader)?;
            let aggregate = read_pubkey(reader)?;
            let leaf_hash = reader.take_option(|r| r.take_array())?;
            let nonce = reader.take_array()?;
            Ok(response::SignatureEntry::MusigPubNonce {
                input_index,
                participant,
                aggregate,
                leaf_hash,
                nonce,
            })
        }
        response::SignatureKind::MusigPartialSig => {
            let participant = read_pubkey(reader)?;
            let aggregate = read_pubkey(reader)?;
            let leaf_hash = reader.take_option(|r| r.take_array())?;
            let signature = reader.take_array()?;
            Ok(response::SignatureEntry::MusigPartialSig {
                input_index,
                participant,
                aggregate,
                leaf_hash,
                signature,
            })
        }
        response::SignatureKind::SpEcdhShare => {
            let scope = read_sp_scope(reader, input_index)?;
            let scan_key = read_pubkey(reader)?;
            let share = read_pubkey(reader)?;
            Ok(response::SignatureEntry::SpEcdhShare {
                scope,
                scan_key,
                share,
            })
        }
        response::SignatureKind::SpDleqProof => {
            let scope = read_sp_scope(reader, input_index)?;
            let scan_key = read_pubkey(reader)?;
            let proof = reader.take_array()?;
            Ok(response::SignatureEntry::SpDleqProof {
                scope,
                scan_key,
                proof,
            })
        }
        response::SignatureKind::Unknown(kind) => Ok(response::SignatureEntry::Unknown {
            input_index,
            kind,
            fields: reader.take_rest().to_vec(),
        }),
    }
}

fn read_sp_scope(reader: &mut Reader<'_>, input_index: u32) -> Result<response::SpScope, Error> {
    response::SpScope::from_wire(reader.take_bool()?, input_index)
        .ok_or(Error::GlobalInputIndex(input_index))
}

fn read_path(reader: &mut Reader<'_>) -> Result<DerivationPath, Error> {
    let count = reader.take_u8()? as usize;
    // the count is one byte, so this allocates at most 255 children
    let mut children = Vec::with_capacity(count);
    for _ in 0..count {
        children.push(reader.take_u32_be()?);
    }
    Ok(DerivationPath(children))
}

fn read_descriptor_alias(reader: &mut Reader<'_>) -> Result<String, Error> {
    Ok(reader.take_string_with_limit(MAX_DESCRIPTOR_ALIAS)?)
}

fn read_extended_key(reader: &mut Reader<'_>) -> Result<ExtendedKey, Error> {
    Ok(ExtendedKey(reader.take_array()?))
}

fn read_fingerprint(reader: &mut Reader<'_>) -> Result<Fingerprint, Error> {
    Ok(Fingerprint(reader.take_array()?))
}

fn read_capabilites(reader: &mut Reader<'_>) -> Result<response::Capabilities, Error> {
    Ok(response::Capabilities(reader.take_u32_be()?))
}

fn read_pubkey(reader: &mut Reader<'_>) -> Result<PublicKey, Error> {
    Ok(PublicKey(reader.take_array()?))
}

fn read_secret_key(reader: &mut Reader<'_>) -> Result<SecretKey, Error> {
    Ok(SecretKey(reader.take_array()?))
}

fn read_version(reader: &mut Reader<'_>) -> Result<response::FirmwareVersion, Error> {
    let major = reader.take_u16_be()?;
    let minor = reader.take_u16_be()?;
    let patch = reader.take_u16_be()?;
    let channel = reader.take_u8()?;
    let number = reader.take_u8()?;
    let flag = response::ReleaseFlag::try_from([channel, number])?;
    Ok(response::FirmwareVersion {
        major,
        minor,
        patch,
        flag,
    })
}

fn read_sign_response_kind(reader: &mut Reader<'_>) -> Result<SignResponseKind, Error> {
    SignResponseKind::try_from(reader.take_u8()?)
}

// WANT_KIND is a preference, so an unknown value reads as absent rather than failing
fn read_want_kind(reader: &mut Reader<'_>) -> Result<Option<SignResponseKind>, Error> {
    Ok(read_sign_response_kind(reader).ok())
}
