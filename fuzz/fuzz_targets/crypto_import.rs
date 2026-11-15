//! pgpsplit's keyed key-import path on attacker-controlled key material:
//! the GnuPG secret-MPI re-encoder `mpi::canonical_secret_mpis`, which walks packet framing and MPIs itself before
//! rPGP sees the key, and the whole OP_IMPORT_KEY op in the keyed mode. The first byte picks the path:
//! - 0: the re-encoder on the raw bytes;
//! - 1: the rest is a secret-key packet *body*, framed here as tag 5 or 7 in the new or old format, so mutations go to
//!   the version/algorithm/MPI walk instead of the framing;
//! - 2: OP_IMPORT_KEY through `handle_bytes(Mode::Keyed, ..)` (re-encoder, rPGP parse, password removal, bindings).
//!
//! Invariants of the re-encoder (any input): never panics; idempotent (its output is already canonical, so a second
//! pass changes nothing); grows the input by at most 4 bytes per packet (a re-emitted packet gets a 6-byte header,
//! the original had at least 2, and the canonical body is never longer).
#![no_main]

use pgpsplit::{Mode, handle_bytes, mpi::canonical_secret_mpis};
use proto::v1::crypto::{CryptoRequest, Op, SecretKey};
use libfuzzer_sys::fuzz_target;
use prost::Message;

fn check(input: Vec<u8>) {
    let len = input.len();
    let once = canonical_secret_mpis(input);
    // every packet has at least a 2-byte header
    assert!(
        once.len() <= len + 4 * (len / 2 + 1),
        "re-encoder grew {len} bytes to {}",
        once.len()
    );
    let twice = canonical_secret_mpis(once.clone());
    assert_eq!(twice, once, "re-encoder output is not canonical");
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    match sel % 3 {
        0 => check(rest.to_vec()),
        1 => {
            let tag = if sel & 0x10 == 0 { 5u8 } else { 7u8 };
            let mut pkt = Vec::with_capacity(rest.len() + 6);
            if sel & 0x20 == 0 {
                pkt.push(0xC0 | tag);
                pkt.push(255);
                pkt.extend_from_slice(&(rest.len() as u32).to_be_bytes());
            } else {
                pkt.push(0x80 | (tag << 2) | 2);
                pkt.extend_from_slice(&(rest.len() as u32).to_be_bytes());
            }
            pkt.extend_from_slice(rest);
            check(pkt);
        }
        _ => {
            let passphrase = (sel & 0x10 != 0).then(|| b"fuzz".to_vec());
            let req = CryptoRequest {
                op: Op::ImportKey as i32,
                secret_keys: vec![SecretKey {
                    key: rest.to_vec(),
                    passphrase,
                }],
                ..Default::default()
            };
            let _ = handle_bytes(Mode::Keyed, &req.encode_to_vec());
        }
    }
});
