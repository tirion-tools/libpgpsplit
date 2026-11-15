//! pgpsplit's parsing of attacker-controlled OpenPGP bytes (rPGP's certificate semantics and packet parser need their own fuzzing). The first byte picks the
//! path: the structural packet scan + container decision (the SED refusal relies on it), or one keyless op through
//! `handle` (decrypt with a fixed session key, detached/inline/cleartext verify against the input as a cert, cert
//! info). Must never panic; every outcome is a response.
#![no_main]

use pgpsplit::{Mode, handle_bytes, ops};
use proto::v1::crypto::{CryptoRequest, Op, SessionKey};
use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let half = rest.len() / 2;
    let req = match sel % 6 {
        0 => {
            let tags = ops::scan(rest);
            assert!(tags.len() <= 64);
            let _ = ops::container(&tags);
            return;
        }
        1 => CryptoRequest {
            op: Op::DecryptSession as i32,
            data: rest.to_vec(),
            session_key: Some(SessionKey {
                version: 3,
                sym_alg: 9,
                key: vec![7; 32],
            }),
            ..Default::default()
        },
        2 => CryptoRequest {
            op: Op::VerifyDetached as i32,
            data: rest[..half].to_vec(),
            signature: rest[half..].to_vec(),
            certs: vec![rest[half..].to_vec()],
            ..Default::default()
        },
        3 => CryptoRequest {
            op: Op::VerifyMessage as i32,
            data: rest.to_vec(),
            ..Default::default()
        },
        4 => CryptoRequest {
            op: Op::VerifyCleartext as i32,
            data: rest.to_vec(),
            ..Default::default()
        },
        _ => CryptoRequest {
            op: Op::CertInfo as i32,
            certs: vec![rest.to_vec()],
            ..Default::default()
        },
    };
    let _ = handle_bytes(Mode::Keyless, &req.encode_to_vec());
});
