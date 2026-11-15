//! Parsing of attacker-controlled OpenPGP bytes (rPGP's certificate semantics and packet parser need their own
//! fuzzing). The first byte picks the path:
//! - 0: the structural packet scan + container decision the SED refusal relies on, through `keyed::unwrap` with no
//!   keys (it scans, refuses SED, then refuses for want of a key);
//! - 1-5: one keyless operation: decrypt with a fixed session key, detached verify against the input as a cert,
//!   inline verify, cleartext verify, cert info.
//!
//! Must never panic; every outcome is a value or a refusal.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pgpsplit::{MAX_PLAINTEXT, Reason, SessionKey, keyed, keyless};

const NO_CERTS: &[&[u8]] = &[];

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let half = rest.len() / 2;
    match sel % 6 {
        0 => {
            let r = keyed::unwrap(rest, &[]);
            assert!(matches!(
                r.map_err(|e| e.reason),
                Err(Reason::NoKey | Reason::NoIntegrity | Reason::Malformed)
            ));
        }
        1 => {
            let key = SessionKey::V3 {
                sym_alg: 9,
                key: vec![7; 32],
            };
            if let Ok(d) = keyless::decrypt(rest, &key, NO_CERTS) {
                assert!(d.payload.len() as u64 <= MAX_PLAINTEXT);
            }
        }
        2 => {
            let _ = keyless::verify_detached(&rest[..half], &rest[half..], &[&rest[half..]]);
        }
        3 => {
            if let Ok(v) = keyless::verify_message(rest, NO_CERTS) {
                assert!(v.payload.len() as u64 <= MAX_PLAINTEXT);
            }
        }
        4 => {
            let _ = keyless::verify_cleartext(rest, NO_CERTS);
        }
        _ => {
            let _ = keyless::cert_info(rest);
        }
    }
});
