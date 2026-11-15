//! pgpsplit: one OpenPGP operation per process on rPGP. `proto/crypto.proto` has the descriptor contract.
//!
//! Two modes, chosen by the launcher kind:
//! - [`Mode::Keyed`] (`--kind=crypto-keyed`): OP_UNWRAP parses only the PKESK packets in front of the encrypted payload
//!   and returns the session key; OP_IMPORT_KEY strips the passphrase and canonicalises GnuPG's non-minimal
//!   secret MPIs ([`mpi::canonical_secret_mpis`]).
//! - [`Mode::Keyless`] (`--kind=crypto`): decrypt with a session key, verify, cert info. Refuses secret keys.
//!
//! Policy decided here: SED (no integrity) is never decrypted; SEIPDv1 is read completely and its MDC checked
//! before any plaintext leaves; GnuPG OCB is accepted; plaintext is capped at 64 MiB (decompression bombs); SHA-1/MD5
//! data signatures are weak, never good; the literal-data file name is never returned. There is no session-key
//! cache anywhere: the session key exists in the caller only between the two helper runs.

pub mod cert;
pub mod mpi;
pub mod ops;

use proto::v1::crypto::{CryptoRequest, CryptoResponse, Op, Reason, Status};
use prost::Message as _;

/// Largest request (fd 0) and largest plaintext released.
pub const MAX_REQUEST: u64 = 64 << 20;
pub const MAX_PLAINTEXT: u64 = 64 << 20;
const MAX_DETAIL: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Keyed,
    Keyless,
}

impl Mode {
    pub fn allows(self, op: Op) -> bool {
        match self {
            Mode::Keyed => matches!(op, Op::Unwrap | Op::ImportKey),
            Mode::Keyless => matches!(
                op,
                Op::DecryptSession
                    | Op::VerifyDetached
                    | Op::VerifyCleartext
                    | Op::VerifyMessage
                    | Op::CertInfo
            ),
        }
    }
}

pub(crate) type Refusal = (Reason, String);
pub(crate) type R = Result<CryptoResponse, Refusal>;

pub(crate) fn e<E: std::fmt::Display>(reason: Reason) -> impl FnOnce(E) -> Refusal {
    move |err| (reason, err.to_string())
}

pub fn refused(op: i32, reason: Reason, detail: &str) -> CryptoResponse {
    let mut d = detail.to_string();
    if d.len() > MAX_DETAIL {
        let mut cut = MAX_DETAIL;
        while !d.is_char_boundary(cut) {
            cut -= 1;
        }
        d.truncate(cut);
    }
    CryptoResponse {
        op,
        status: Status::Refused as i32,
        reason: reason as i32,
        detail: d,
        ..Default::default()
    }
}

/// One request in, one response out. Never panics on hostile input it can refuse (rPGP panics are bugs: the process
/// exits and the caller shows "could not open").
pub fn handle(mode: Mode, request: &[u8]) -> CryptoResponse {
    let req = match CryptoRequest::decode(request) {
        Ok(r) => r,
        Err(err) => return refused(0, Reason::Protocol, &err.to_string()),
    };
    let op = Op::try_from(req.op).unwrap_or(Op::Unspecified);
    if !mode.allows(op) {
        return refused(req.op, Reason::Protocol, "op not allowed in this mode");
    }
    if mode == Mode::Keyless && !req.secret_keys.is_empty() {
        return refused(
            req.op,
            Reason::Protocol,
            "secret key sent to the keyless helper",
        );
    }
    let r = match op {
        Op::Unwrap => ops::unwrap(&req),
        Op::ImportKey => ops::import_key(&req),
        Op::DecryptSession => ops::decrypt_session(&req),
        Op::VerifyDetached => ops::verify_detached(&req),
        Op::VerifyCleartext => ops::verify_cleartext(&req),
        Op::VerifyMessage => ops::verify_message(&req),
        Op::CertInfo => ops::cert_info(&req),
        Op::Unspecified => Err((Reason::Protocol, "unknown op".into())),
    };
    match r {
        Ok(mut resp) => {
            resp.op = req.op;
            resp.status = Status::Ok as i32;
            resp
        }
        Err((reason, detail)) => refused(req.op, reason, &detail),
    }
}

/// [`handle`], encoded.
pub fn handle_bytes(mode: Mode, request: &[u8]) -> Vec<u8> {
    handle(mode, request).encode_to_vec()
}
