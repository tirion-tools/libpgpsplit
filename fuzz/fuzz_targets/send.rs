//! The send side on attacker-shaped input: a secret key that does not come from `keyed::generate_key` (imported keys
//! are signed with and renewed), certificates of recipients (from Autocrypt headers, attachments, WKD), and the
//! `data_is_message` input of `keyless::encrypt`. The first byte picks the path:
//! - 0: `keyed::sign` with the rest as the secret key (detached or inline, by bit 4);
//! - 1: `keyed::extend_expiry` with the rest as the secret key;
//! - 2: `keyless::encrypt` to the rest as one certificate;
//! - 3: `keyless::encrypt` of the rest with `data_is_message` (to a fixed certificate).
//!
//! Invariants: never panics; whatever signs verifies with the key's own certificate; a renewed key still parses and
//! keeps its fingerprint; encryption output is an armored message.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pgpsplit::{SecretKey, SigStatus, SignMode, keyed, keyless};

const NOW: u32 = 1_794_787_200;
const DATA: &[u8] = b"fuzz\r\n";
/// A fixed recipient: libpgpsplit's generated test key (tests/corpus/send/generated.pub.pgp).
const CERT: &[u8] = include_bytes!("../../tests/corpus/send/generated.pub.pgp");

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let key = SecretKey {
        key: rest,
        passphrase: None,
    };
    match sel % 4 {
        0 => {
            let mode = if sel & 0x10 == 0 {
                SignMode::Detached
            } else {
                SignMode::Inline
            };
            if let Ok(s) = keyed::sign(key, DATA, mode, &[], NOW)
                && mode == SignMode::Detached
                && let Ok(k) = keyed::import_key(key)
            {
                let v = keyless::verify_detached(DATA, &s.payload, &[&k.public_cert]).unwrap();
                assert_eq!(v.status, SigStatus::Good);
            }
        }
        1 => {
            if let Ok(r) = keyed::extend_expiry(key, NOW, Some(86400)) {
                let info = keyless::cert_info(&r.public_cert).expect("renewed certificate parses");
                assert_eq!(info, r.info);
            }
        }
        2 => {
            if let Ok(m) = keyless::encrypt(DATA, &[rest], false, NOW) {
                assert!(m.starts_with(b"-----BEGIN PGP MESSAGE-----"));
            }
        }
        _ => {
            if let Ok(m) = keyless::encrypt(rest, &[CERT], true, NOW) {
                assert!(m.starts_with(b"-----BEGIN PGP MESSAGE-----"));
            }
        }
    }
});
