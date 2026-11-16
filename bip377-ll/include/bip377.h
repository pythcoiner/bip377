/* C binding for the QR signing codec, signer direction.
 *
 * Kept in sync by hand with src/ffi/types.rs. The wire format is
 * specified in ENCODING.md.
 *
 * Ownership: this library never frees memory you own, and you never free memory it
 * owns except through bip377_request_free and bip377_buf_free. On encode your struct
 * is borrowed for the duration of the call only.
 */

#ifndef BIP377_H
#define BIP377_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BIP377_REQUEST_ID_LEN 2
#define BIP377_MAX_DESCRIPTOR_ALIAS 32
#define BIP377_EXTENDED_KEY_LEN 78
#define BIP377_FINGERPRINT_LEN 4
#define BIP377_PUBLIC_KEY_LEN 33
#define BIP377_SECRET_KEY_LEN 32
#define BIP377_MUSIG_PUB_NONCE_LEN 66
#define BIP377_MUSIG_PARTIAL_SIG_LEN 32
#define BIP377_TAP_LEAF_HASH_LEN 32
#define BIP377_DLEQ_PROOF_LEN 64
#define BIP377_SCHNORR_SIGNATURE_LEN 64 /* 65 with a sighash type byte */

/* Sizes and limits stay macros: they are array dimensions and a consumer may want
 * them in an #if. Everything a field can hold is an enum below.
 *
 * No field or return type is declared as one of these enum types. A C enum's size is
 * implementation-defined while the wire fields are one byte, so the structs use
 * uint8_t and the functions return int32_t. The enums name the values, they do not
 * type them. */

/* Closed: the decoder rejects any other value. */
enum bip377_message_type {
    /* only in an error response whose id is {0x00, 0x00} */
    BIP377_MESSAGE_UNREADABLE_REQUEST = 0x00,
    BIP377_MESSAGE_GET_INFO = 0x01, /* no request body: the body union is unused */
    BIP377_MESSAGE_GET_KEYS = 0x02,
    BIP377_MESSAGE_REGISTER_DESCRIPTOR = 0x03,
    BIP377_MESSAGE_ADDRESS_VERIFICATION = 0x04,
    BIP377_MESSAGE_SIGNING = 0x05,
    BIP377_MESSAGE_NONCE_PREPARATION = 0x06,
    BIP377_MESSAGE_UNREGISTER_DESCRIPTOR = 0x07
};

enum bip377_capability {
    BIP377_CAPABILITY_BIP380_DESCRIPTORS = 1u << 0,
    BIP377_CAPABILITY_BIP388_WALLET_POLICIES = 1u << 1,
    BIP377_CAPABILITY_MINISCRIPT_SEGWIT_V0 = 1u << 2,
    BIP377_CAPABILITY_MINISCRIPT_TAPROOT = 1u << 3,
    BIP377_CAPABILITY_SILENT_PAYMENT_SENDS = 1u << 4,
    BIP377_CAPABILITY_SILENT_PAYMENT_ACCOUNTS = 1u << 5,
    BIP377_CAPABILITY_UNREGISTER_DESCRIPTOR = 1u << 6,
    BIP377_CAPABILITY_MUSIG2 = 1u << 7,
    BIP377_CAPABILITY_NONCE_CACHE = 1u << 8
};

/* Open: a value outside this list is a newer state, which counts as not ready. To
 * encode, it must sit above BIP377_STATE_UNINITIALIZED. */
enum bip377_state {
    BIP377_STATE_READY = 0x00,
    BIP377_STATE_LOCKED = 0x01,
    BIP377_STATE_UNINITIALIZED = 0x02
};

/* Encoding a response rejects any other bit. */
enum bip377_network {
    BIP377_NETWORK_MAINNET = 1u << 1,
    BIP377_NETWORK_TESTNET = 1u << 2,
    BIP377_NETWORK_SIGNET = 1u << 3,
    BIP377_NETWORK_REGTEST = 1u << 4
};

/* Closed: the decoder rejects any other value. */
enum bip377_key_kind {
    BIP377_KEY_PUBLIC = 0x00,
    BIP377_KEY_PRIVATE = 0x01
};

/* Closed: the decoder rejects any other value. */
enum bip377_descriptor_form {
    BIP377_DESCRIPTOR_BIP380 = 0x01,
    BIP377_DESCRIPTOR_BIP388 = 0x02,
    BIP377_DESCRIPTOR_SP_KEYS = 0x03
};

/* Closed: the decoder rejects any other value. */
enum bip377_sign_response_kind {
    BIP377_SIGN_RESPONSE_PSBT = 0x01,
    BIP377_SIGN_RESPONSE_SIGNATURES = 0x02
};

/* Closed: encoding a response rejects any other value. */
enum bip377_signature_kind {
    BIP377_SIGNATURE_ECDSA = 0x01,
    BIP377_SIGNATURE_TAP_KEY = 0x02,
    BIP377_SIGNATURE_TAP_SCRIPT = 0x03,
    BIP377_SIGNATURE_MUSIG_PUB_NONCE = 0x04,
    BIP377_SIGNATURE_MUSIG_PARTIAL_SIG = 0x05,
    BIP377_SIGNATURE_SP_ECDH_SHARE = 0x06,
    BIP377_SIGNATURE_SP_DLEQ_PROOF = 0x07
};

/* Open: a value outside this list is a newer flag and passes through unchanged. */
enum bip377_release_flag {
    BIP377_RELEASE_STABLE = 0x00,
    BIP377_RELEASE_ALPHA = 0x01,
    BIP377_RELEASE_BETA = 0x02,
    BIP377_RELEASE_CANDIDATE = 0x03
};

/* Open: a value outside this list passes through as an unknown code, and must sit in
 * 0x11..=0xfe to encode. */
enum bip377_response_error {
    BIP377_RESPONSE_ERROR_USER_DECLINED = 0x01,
    BIP377_RESPONSE_ERROR_UNSUPPORTED_VERSION = 0x02,
    BIP377_RESPONSE_ERROR_MALFORMED_REQUEST = 0x03,
    BIP377_RESPONSE_ERROR_UNKNOWN_DESCRIPTOR_ALIAS = 0x04,
    BIP377_RESPONSE_ERROR_DESCRIPTOR_REGISTRATION_FAILED = 0x05,
    BIP377_RESPONSE_ERROR_UNSUPPORTED_DESCRIPTOR_FORM = 0x06,
    BIP377_RESPONSE_ERROR_INVALID_PROOF = 0x07,
    BIP377_RESPONSE_ERROR_ADDRESS_MISMATCH = 0x08,
    BIP377_RESPONSE_ERROR_NOTHING_TO_SIGN = 0x09,
    BIP377_RESPONSE_ERROR_INVALID_PSBT = 0x0a,
    BIP377_RESPONSE_ERROR_INTERNAL = 0x0b,
    BIP377_RESPONSE_ERROR_PRIVATE_KEY_EXPORT_REFUSED = 0x0c,
    BIP377_RESPONSE_ERROR_MUSIG_SESSION = 0x0d,
    BIP377_RESPONSE_ERROR_ALREADY_REGISTERED = 0x0e,
    BIP377_RESPONSE_ERROR_UNSUPPORTED_OPERATION = 0x0f,
    BIP377_RESPONSE_ERROR_NETWORK_MISMATCH = 0x10,
    BIP377_RESPONSE_ERROR_VENDOR = 0xff
};

/* Selects the scan arm of bip377_sp_keys. Not a wire value: the wire carries the
 * scan path and the scan key as two optional fields, exactly one present. */
enum bip377_scan_kind {
    BIP377_SCAN_PATH = 0x00, /* the signer's own scan key, at scan.path */
    BIP377_SCAN_KEY = 0x01   /* a scan private key the signer does not hold */
};

enum bip377_absent {
    BIP377_ABSENT_BOOL = -1,
    BIP377_ABSENT_KIND = -1
};

/* What the four functions return. 100..=199 come from the byte reader, 200..=299
 * from the decoder, 300..=399 from the encoder, 400..=499 from this binding and
 * 500..=599 from a protocol rule the message breaks, both on encode and decode. */
enum bip377_status {
    BIP377_OK = 0,

    BIP377_ERR_TRUNCATED = 100,
    BIP377_ERR_LENGTH_OVERFLOW = 101,
    BIP377_ERR_NON_CANONICAL_COMPACT_SIZE = 102,
    BIP377_ERR_COMPACT_SIZE_TOO_LARGE = 103,
    BIP377_ERR_INVALID_BOOL = 104,
    BIP377_ERR_INVALID_PRESENCE = 105,
    BIP377_ERR_STRING_TOO_LARGE = 106,
    BIP377_ERR_INVALID_UTF8 = 110,
    BIP377_ERR_STRING_NUL = 111,

    BIP377_ERR_INVALID_MAGIC = 200,
    BIP377_ERR_RESERVED_VERSION = 201,
    BIP377_ERR_UNKNOWN_MESSAGE_TYPE = 202,
    BIP377_ERR_ERROR_STATUS_ON_REQUEST = 203,
    BIP377_ERR_UNKNOWN_DESCRIPTOR_FORM = 204,
    BIP377_ERR_UNKNOWN_SIGN_RESPONSE_KIND = 206,
    BIP377_ERR_UNKNOWN_KEY_KIND = 207,
    BIP377_ERR_SIGNATURE_LENGTH = 208,
    BIP377_ERR_GLOBAL_INPUT_INDEX = 209,
    BIP377_ERR_SCAN_PATH_AND_KEY = 210,
    BIP377_ERR_NO_SCAN = 211,
    BIP377_ERR_UNPAIRED_SESSION = 212,
    BIP377_ERR_UNREADABLE_REQUEST_TYPE = 213,

    BIP377_ERR_PATH_TOO_LONG = 300,
    BIP377_ERR_PATCH_TOO_LARGE = 301,
    BIP377_ERR_RESERVED_CAPABILITY_BITS = 302,
    BIP377_ERR_ERROR_CODE_OUT_OF_RANGE = 303,
    BIP377_ERR_STRING_TOO_LONG = 306,
    BIP377_ERR_ENCODE_STRING_NUL = 307,
    BIP377_ERR_UNREACHABLE = 309,
    BIP377_ERR_DEFINED_SIGNATURE_KIND = 310,
    BIP377_ERR_RESERVED_NETWORK_BITS = 311,
    BIP377_ERR_DEFINED_STATE = 312,
    BIP377_ERR_DEFINED_RELEASE_FLAG = 313,

    BIP377_ERR_NULL_POINTER = 400,
    BIP377_ERR_FFI_STRING_NUL = 401,
    BIP377_ERR_FFI_INVALID_UTF8 = 402,
    BIP377_ERR_FFI_INVALID_BOOL = 403,
    BIP377_ERR_UNKNOWN_TAG = 404,
    BIP377_ERR_UNEXPECTED_RESPONSE = 406,
    BIP377_ERR_FFI_GLOBAL_INPUT_INDEX = 407,

    BIP377_ERR_DUPLICATE_SP_SHARE = 500,
    BIP377_ERR_DUPLICATE_SP_PROOF = 501,
    BIP377_ERR_MISSING_SP_PROOF = 502,
    BIP377_ERR_MISSING_SP_SHARE = 503,
    BIP377_ERR_MAX_ALIAS_TOO_LARGE = 504,
    BIP377_ERR_FINGERPRINT_WHEN_NOT_READY = 505,
    BIP377_ERR_TAPROOT_SIGNATURE_LENGTH = 506,
    BIP377_ERR_ZERO_MAX_INPUTS = 507,
    BIP377_ERR_REVERSED_EXPRESSION_RANGE = 508,
    BIP377_ERR_SESSION_REF_WITHOUT_ID = 509,
    BIP377_ERR_UNREADABLE_REQUEST_ID = 510
};

/* A borrowed run of items. A NULL ptr means the field is absent, which is distinct
 * from a present but empty run (non-NULL ptr with len 0). */
typedef struct {
    const uint8_t *ptr;
    size_t len;
} bip377_bytes;

/* BIP-32 child numbers with the hardened bit set. */
typedef struct {
    const uint32_t *ptr;
    uint8_t len;
} bip377_path;

typedef struct {
    bip377_path derivation_path;
    uint8_t kind; /* BIP377_KEY_* */
} bip377_key_request;

typedef struct {
    const bip377_key_request *ptr;
    size_t len;
} bip377_key_request_list;

typedef struct {
    const char *const *ptr;
    size_t len;
} bip377_string_list;

/* BIP-32 serialization of an extended public or private key. */
typedef struct {
    uint8_t bytes[BIP377_EXTENDED_KEY_LEN];
} bip377_extended_key;

typedef struct {
    const bip377_extended_key *ptr;
    size_t len;
} bip377_extended_key_list;

/* Strings are UTF-8 and NUL-terminated. The codec rejects an interior NUL on both
 * sides, so a string never carries one. A NULL pointer means the field is absent. */

typedef struct {
    bip377_string_list keys;
    const char *policy;
} bip377_bip388;

typedef union {
    bip377_path path;                     /* from the master key */
    uint8_t key[BIP377_SECRET_KEY_LEN];   /* big-endian scalar */
} bip377_scan_value;

typedef struct {
    uint8_t fingerprint[BIP377_FINGERPRINT_LEN];
    bip377_path spend_path; /* from the master key */
    uint8_t scan_kind;      /* BIP377_SCAN_*, selects the scan arm */
    bip377_scan_value scan;
} bip377_sp_keys;

typedef union {
    const char *bip380;
    bip377_bip388 bip388;
    bip377_sp_keys sp_keys;
} bip377_descriptor_value;

typedef struct {
    uint8_t tag; /* BIP377_DESCRIPTOR_* */
    bip377_descriptor_value value;
} bip377_descriptor_body;

typedef struct {
    const char *alias;
    const bip377_descriptor_body *body;
    bip377_bytes proof;
} bip377_descriptor;

typedef struct {
    const bip377_descriptor *ptr;
    size_t len;
} bip377_descriptor_list;

typedef struct {
    bip377_key_request_list keys;
} bip377_get_keys;

typedef struct {
    const char *descriptor_alias;
    const bip377_descriptor_body *descriptor; /* NULL when absent */
} bip377_register_descriptor;

typedef struct {
    const char *descriptor_alias;
} bip377_unregister_descriptor;

typedef struct {
    const char *descriptor_alias;
    bip377_path derivation_path;
    const char *address;                      /* NULL when absent */
    const bip377_descriptor_body *descriptor; /* NULL when absent */
    bip377_bytes proof;                       /* ptr NULL when absent */
} bip377_verify_address;

typedef struct {
    bip377_descriptor_list descriptors;
    bip377_bytes psbt; /* BIP-174 serialization, carried unparsed */
    int16_t want_kind; /* BIP377_SIGN_RESPONSE_* or BIP377_ABSENT_KIND */
    bool accept_trimmed; /* a PSBT answer may leave out fields of psbt */
} bip377_sign;

/* start..=end: key expression indexes, start <= end; start alone without end. */
typedef struct {
    uint8_t has_session_id; /* 0 or 1, the signer draws one when 0 */
    uint8_t session_id[4];
    uint8_t has_session_ref; /* 0 or 1 */
    uint8_t session_ref[4];
    const bip377_descriptor *descriptor; /* NULL when absent */
    uint32_t max_inputs;
    bip377_path derivation_path; /* from the master key */
    uint32_t start;
    uint8_t has_end; /* 0 or 1 */
    uint32_t end;
} bip377_prepare_nonces;

typedef union {
    bip377_get_keys get_keys;
    bip377_register_descriptor register_descriptor;
    bip377_verify_address verify_address;
    bip377_sign sign;
    bip377_prepare_nonces prepare_nonces;
    bip377_unregister_descriptor unregister_descriptor;
} bip377_request_body;

typedef struct {
    uint8_t id[BIP377_REQUEST_ID_LEN];
    uint8_t message_type; /* BIP377_MESSAGE_*, selects the body arm */
    bip377_request_body body;
} bip377_request;

typedef struct {
    uint16_t major;
    uint16_t minor;
    uint32_t patch; /* at most 0x00ffffff */
    uint8_t flag;   /* BIP377_RELEASE_* */
} bip377_firmware_version;

typedef struct {
    bip377_extended_key_list keys; /* one per request key, in request order */
    uint8_t fingerprint[BIP377_FINGERPRINT_LEN];
    const char *vendor;
    const char *model;
    bip377_firmware_version version;
    uint32_t capabilities; /* only the low nine bits may be set */
} bip377_keys;

typedef struct {
    const char *vendor;
    const char *model;
    bip377_firmware_version version;
    uint32_t capabilities;   /* only the low nine bits may be set */
    uint8_t state;           /* BIP377_STATE_* */
    uint8_t networks;        /* BIP377_NETWORK_* bits */
    uint32_t max_message;    /* bytes */
    uint8_t max_alias;       /* at most BIP377_MAX_DESCRIPTOR_ALIAS */
    uint8_t has_fingerprint; /* 0 or 1, and 1 only when state is BIP377_STATE_READY */
    uint8_t fingerprint[BIP377_FINGERPRINT_LEN];
} bip377_info;

typedef struct {
    const char *descriptor_alias;
    bool registered;
    int8_t stored;       /* 0, 1 or BIP377_ABSENT_BOOL */
    bip377_bytes proof;
} bip377_registration;

/* The alias is no longer registered once this is sent. */
typedef struct {
    const char *descriptor_alias;
} bip377_unregistered;

typedef struct {
    const char *uri; /* BIP-321 payment URI for the verified address */
} bip377_address_uri;

typedef struct {
    uint8_t public_key[BIP377_PUBLIC_KEY_LEN]; /* compressed */
    bip377_bytes signature;
} bip377_ecdsa;

typedef struct {
    bip377_bytes signature;
} bip377_tap_key;

typedef struct {
    uint8_t xonly_public_key[32];
    uint8_t tap_leaf_hash[32];
    bip377_bytes signature;
} bip377_tap_script;

typedef struct {
    uint8_t participant[BIP377_PUBLIC_KEY_LEN];
    uint8_t aggregate[BIP377_PUBLIC_KEY_LEN];
    uint8_t has_leaf_hash; /* 0 or 1 */
    uint8_t leaf_hash[BIP377_TAP_LEAF_HASH_LEN];
    uint8_t nonce[BIP377_MUSIG_PUB_NONCE_LEN];
} bip377_musig_pub_nonce;

typedef struct {
    uint8_t participant[BIP377_PUBLIC_KEY_LEN];
    uint8_t aggregate[BIP377_PUBLIC_KEY_LEN];
    uint8_t has_leaf_hash; /* 0 or 1 */
    uint8_t leaf_hash[BIP377_TAP_LEAF_HASH_LEN];
    uint8_t signature[BIP377_MUSIG_PARTIAL_SIG_LEN];
} bip377_musig_partial_sig;

typedef struct {
    uint8_t global; /* 0 for the input at input_index, 1 for the whole transaction */
    uint8_t scan_key[BIP377_PUBLIC_KEY_LEN];
    uint8_t share[BIP377_PUBLIC_KEY_LEN];
} bip377_sp_ecdh_share;

typedef struct {
    uint8_t global; /* 0 for the input at input_index, 1 for the whole transaction */
    uint8_t scan_key[BIP377_PUBLIC_KEY_LEN];
    uint8_t proof[BIP377_DLEQ_PROOF_LEN]; /* BIP-374 */
} bip377_sp_dleq_proof;

typedef struct {
    uint8_t bytes[BIP377_MUSIG_PUB_NONCE_LEN];
} bip377_pub_nonce;

typedef struct {
    const bip377_pub_nonce *ptr;
    size_t len;
} bip377_pub_nonce_list;

/* nonces: (end - start + 1) * max_inputs entries of the request, the one for key
 * expression index j and input i at (j - start) * max_inputs + i. */
typedef struct {
    uint8_t has_session; /* 0 or 1, 1 only for a new session */
    uint8_t session_id[4];
    uint8_t session_ref[4];
    bip377_pub_nonce_list nonces;
} bip377_nonces_prepared;

typedef union {
    bip377_ecdsa ecdsa;
    bip377_tap_key tap_key;
    bip377_tap_script tap_script;
    bip377_musig_pub_nonce musig_pub_nonce;
    bip377_musig_partial_sig musig_partial_sig;
    bip377_sp_ecdh_share sp_ecdh_share;
    bip377_sp_dleq_proof sp_dleq_proof;
} bip377_signature_value;

typedef struct {
    uint32_t input_index; /* 0 for a global silent payment entry */
    uint8_t kind; /* BIP377_SIGNATURE_*, selects the value arm */
    bip377_signature_value value;
} bip377_signature;

typedef struct {
    const bip377_signature *ptr;
    size_t len;
} bip377_signature_list;

typedef union {
    bip377_bytes psbt;
    bip377_signature_list signatures;
} bip377_signed_value;

typedef struct {
    uint8_t kind; /* BIP377_SIGN_RESPONSE_*, selects the value arm */
    bip377_signed_value value;
} bip377_signed;

typedef struct {
    uint8_t error; /* BIP377_RESPONSE_ERROR_* */
    const char *message;
} bip377_error_body;

typedef union {
    bip377_keys keys;
    bip377_registration registration;
    bip377_address_uri address_uri;
    bip377_signed signed_body;
    bip377_nonces_prepared nonces_prepared;
    bip377_unregistered unregistered;
    bip377_info info;
    bip377_error_body error;
} bip377_response_body;

typedef struct {
    uint8_t id[BIP377_REQUEST_ID_LEN];
    uint8_t message_type; /* BIP377_MESSAGE_*, selects the body arm */
    bool is_error;        /* when true the body is the error arm */
    bip377_response_body body;
} bip377_response;

/* A byte buffer the codec allocated. Release it with bip377_buf_free. */
typedef struct {
    uint8_t *ptr;
    size_t len;
} bip377_buf;

/* Decodes a request. On BIP377_OK, *out owns the tree until bip377_request_free.
 * err may be NULL; otherwise a failure writes a static message to it. */
int32_t bip377_request_decode(const uint8_t *bytes, size_t len,
                              const bip377_request **out, const char **err);

/* Releases a request from bip377_request_decode. NULL is a no-op. */
void bip377_request_free(const bip377_request *request);

/* Encodes a response. On BIP377_OK, *out owns the bytes until bip377_buf_free. */
int32_t bip377_response_encode(const bip377_response *response, bip377_buf *out,
                               const char **err);

/* Releases a buffer from the codec. A NULL ptr is a no-op. */
void bip377_buf_free(bip377_buf buf);

#ifdef __cplusplus
}
#endif

#endif /* BIP377_H */
