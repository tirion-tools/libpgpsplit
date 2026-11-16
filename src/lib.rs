//! pgpsplit: OpenPGP split decryption and verification on rPGP.
//!
//! The API is split by what each half may hold:
//! - [`keyed`] takes (or makes) secret keys: [`keyed::unwrap`] parses only the PKESK packets in front of the encrypted
//!   payload and returns the session key; [`keyed::import_key`] removes the passphrase and canonicalises GnuPG's
//!   non-minimal secret MPIs ([`canonical_secret_mpis`]); [`keyed::sign`] makes a detached or inline signature;
//!   [`keyed::generate_key`] makes a new key.
//! - [`keyless`] never takes a secret key: decrypt with a session key, verify, certificate info, and encryption to
//!   certificates ([`keyless::encrypt`]). It parses the attacker-controlled payload (decompression, literal data,
//!   signatures).
//!
//! Run each half in its own process: the process holding the key then never parses the payload, and the process
//! parsing the payload never holds the key.
//!
//! Policy decided here: SED (no integrity) is never decrypted, and is refused before any key is used; SEIPDv1 is read
//! completely and its MDC checked before any plaintext leaves; GnuPG OCB is accepted; plaintext is capped at
//! [`MAX_PLAINTEXT`] (decompression bombs); SHA-1/MD5/RIPEMD-160 data signatures are weak, never good; the literal-data
//! file name is never returned. There is no session-key cache: the session key exists only in the caller.

mod cert;
pub mod keyed;
pub mod keyless;
mod mpi;
mod packets;

pub use mpi::canonical_secret_mpis;

/// Largest plaintext (and largest dearmored input) released.
pub const MAX_PLAINTEXT: u64 = 64 << 20;

/// [`SignatureVerdict::why`] bits for [`SigStatus::KeyInvalid`].
pub const WHY_REVOKED: u32 = 1;
pub const WHY_NO_VALID_BINDING: u32 = 2;
pub const WHY_NOT_SIGNING_CAPABLE: u32 = 4;
pub const WHY_EXPIRED_AT_SIGNING: u32 = 8;
pub const WHY_PREDATES_KEY: u32 = 16;

/// Why an operation was refused. The discriminants are stable, so a wire format can carry the reason as an integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Reason {
    /// The input is not valid for this operation (an empty session key, an encrypted message to verify).
    InvalidRequest = 1,
    /// The OpenPGP data does not parse.
    Malformed = 2,
    NotEncrypted = 3,
    /// SED (no MDC): never decrypted (EFAIL).
    NoIntegrity = 4,
    /// MDC/AEAD check failed: no plaintext released.
    IntegrityFailure = 5,
    NoKey = 6,
    BadPassphrase = 7,
    BadKey = 8,
    /// Plaintext over [`MAX_PLAINTEXT`] (decompression bombs included).
    TooLarge = 9,
    Unsupported = 10,
    DecryptFailed = 11,
}

/// A refused operation. `detail` is diagnostic only; it never carries plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub reason: Reason,
    pub detail: String,
}

impl Refusal {
    pub(crate) fn new(reason: Reason, detail: impl Into<String>) -> Self {
        Refusal {
            reason,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.reason, self.detail)
    }
}

impl std::error::Error for Refusal {}

pub(crate) fn e<E: std::fmt::Display>(reason: Reason) -> impl FnOnce(E) -> Refusal {
    move |err| Refusal::new(reason, err.to_string())
}

/// The encryption container of a message, from its top-level packets. Stable discriminants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Container {
    None = 1,
    /// SEIPD v1 + MDC, checked before release.
    SeipdV1 = 2,
    /// SEIPD v2 (AEAD).
    SeipdV2 = 3,
    /// GnuPG/LibrePGP OCB Encrypted Data (AEAD).
    Ocbed = 4,
    /// Never decrypted.
    Sed = 5,
    Unknown = 6,
}

/// A session key, as [`keyed::unwrap`] returns it and [`keyless::decrypt`] takes it.
#[derive(Clone, PartialEq, Eq)]
pub enum SessionKey {
    /// From a v3 PKESK: RFC 9580 symmetric algorithm id and key.
    V3 { sym_alg: u8, key: Vec<u8> },
    /// From a v6 PKESK.
    V6 { key: Vec<u8> },
}

/// A transferable secret key (armored or binary) and its passphrase.
#[derive(Clone, Copy)]
pub struct SecretKey<'a> {
    pub key: &'a [u8],
    pub passphrase: Option<&'a [u8]>,
}

/// Verdict for one data signature. Stable discriminants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SigStatus {
    Good = 1,
    /// Cryptographic failure.
    Bad = 2,
    /// The issuer is not among the certificates.
    UnknownKey = 3,
    /// MD5/SHA-1/RIPEMD-160 (or no hash): never good.
    WeakHash = 4,
    /// See [`SignatureVerdict::why`].
    KeyInvalid = 5,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureVerdict {
    pub status: SigStatus,
    /// `WHY_*` bits, set only for [`SigStatus::KeyInvalid`].
    pub why: u32,
    /// Issuer fingerprint, or key id when the signature has no fingerprint (empty when it has neither).
    pub issuer: Vec<u8>,
    /// Signature creation time (Unix seconds).
    pub created: Option<u32>,
    /// RFC 9580 hash algorithm id.
    pub hash_alg: Option<u8>,
    /// The issuing certificate, when it is among the certificates.
    pub signer: Option<Signer>,
    /// Intended Recipient Fingerprint subpackets (hashed area).
    pub intended_recipients: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signer {
    /// Primary key fingerprint.
    pub cert: Vec<u8>,
    /// Fingerprint of the signing (sub)key.
    pub key: Vec<u8>,
    /// Self-certified User IDs.
    pub uids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    pub fingerprint: Vec<u8>,
    /// A valid self-signature binds the key.
    pub valid: bool,
    pub sign: bool,
    pub encrypt: bool,
    pub revoked: bool,
    /// Expiry (Unix seconds); `None` never expires.
    pub expires: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertInfo {
    pub fingerprint: Vec<u8>,
    /// Key version: 4 or 6.
    pub version: u8,
    pub revoked: bool,
    /// Self-certified User IDs.
    pub uids: Vec<String>,
    /// `[0]` is the primary key.
    pub keys: Vec<KeyInfo>,
}

/// [`keyless::decrypt`]: the plaintext and the verdicts of the signatures inside it (combined form).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decrypted {
    pub container: Container,
    pub pkesk_count: u32,
    pub signatures: Vec<SignatureVerdict>,
    pub payload: Vec<u8>,
}

/// [`keyless::verify_cleartext`], [`keyless::verify_message`]: the signed text or literal data, and the verdicts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub signatures: Vec<SignatureVerdict>,
    pub payload: Vec<u8>,
}

/// What [`keyed::sign`] produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignMode {
    /// An ASCII-armored detached binary-document signature over the exact bytes (RFC 3156 §5 multipart/signed).
    Detached,
    /// Binary OpenPGP packets: one-pass signature, literal data (binary, no file name, date 0), signature. The input of
    /// [`keyless::encrypt`] with `data_is_message` (RFC 3156 §6.2 combined sign-then-encrypt).
    Inline,
}

/// [`keyed::sign`]: the signature (detached) or signed message (inline), and its hash algorithm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    pub payload: Vec<u8>,
    /// RFC 9580 hash algorithm id (8 = SHA-256), e.g. for the RFC 3156 `micalg` parameter.
    pub hash_alg: u8,
}

/// [`keyed::generate_key`]: the key and its revocation certificate.
#[derive(Clone)]
pub struct GeneratedKey {
    pub key: KeyPair,
    /// ASCII-armored revocation certificate: the primary key and a key revocation signature (reason "no reason
    /// specified"). Anyone holding it can revoke the key: store it like the secret key, apart from it.
    pub revocation: Vec<u8>,
}

/// [`keyed::extend_expiry`].
#[derive(Clone)]
pub struct RenewedKey {
    /// Binary transferable secret key with the new self-signatures; the secret key packets as given (protection
    /// unchanged).
    pub secret_key: Vec<u8>,
    /// Binary transferable public key of the same key.
    pub public_cert: Vec<u8>,
    pub info: CertInfo,
}

/// [`keyed::import_key`], [`keyed::generate_key`].
#[derive(Clone)]
pub struct KeyPair {
    /// Binary transferable secret key, passphrase removed, secret MPIs canonical.
    pub unprotected_key: Vec<u8>,
    /// Binary transferable public key of the same key.
    pub public_cert: Vec<u8>,
    pub info: CertInfo,
}
