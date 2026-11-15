//! Every OpenPGP fixture of `tests/corpus/eml` through the library, with the profile's keys and certificates
//! (`common::SECRET_KEYS`, `common::CERTS`): PGP/MIME signed parts by `verify_detached` over the canonical signed
//! part, cleartext-signed blocks by `verify_cleartext`, messages by `keyed::unwrap` then `keyless::decrypt`. The
//! outcome of each fixture is fixed in `EXPECTED`.
mod common;

use common::{SECRET_KEYS, armored_in, certs, key, read};
use pgpsplit::{SecretKey, SignatureVerdict, keyed, keyless};

/// Library outcomes, not mail verdicts: MIME-level judgements (a signed part wrapped in attacker MIME, a From that
/// differs from the signer, a partially signed body) are the caller's, so those fixtures verify `Good` here.
const EXPECTED: &[(&str, &str)] = &[
    ("efail-pgp-direct-inline-html", "decrypt SeipdV1 []"),
    ("efail-pgp-direct-mixed", "decrypt SeipdV1 []"),
    ("efail-pgp-mdc-stripped", "unwrap NoIntegrity"),
    ("efail-pgp-mdc-tampered", "decrypt IntegrityFailure"),
    ("gnupg-nonminimal-mpi-key", "decrypt SeipdV1 [Good]"),
    ("gpgarch-inline-enc", "decrypt SeipdV1 []"),
    ("gpgarch-inline-signed", "cleartext [Good]"),
    ("gpgarch-pgpmime-enc-only", "decrypt SeipdV1 []"),
    ("gpgarch-pgpmime-enc-signed", "decrypt SeipdV1 [Good]"),
    ("gpgarch-pgpmime-ocb", "decrypt Ocbed [Good]"),
    ("gpgarch-pgpmime-passphrase-key", "decrypt SeipdV1 [Good]"),
    (
        "gpgarch-pgpmime-protected-headers",
        "decrypt SeipdV1 [Good]",
    ),
    ("gpgarch-pgpmime-rsa-attach", "decrypt SeipdV1 [Good]"),
    ("gpgarch-pgpmime-signed-rsa", "detached [Good]"),
    ("gpgarch-pgpmime-signed-sha1", "detached [WeakHash]"),
    ("gpgarch-pgpmime-signed", "detached [Good]"),
    ("gpgarch-pgpmime-to-rnp", "decrypt SeipdV1 [Good]"),
    ("gpgarch-pgpmime-to-sq-v4", "decrypt SeipdV1 [Good]"),
    ("gpgarch-sigspoof-filename", "decrypt SeipdV1 [Good]"),
    ("gpgdeb-inline-enc", "decrypt SeipdV1 []"),
    ("gpgdeb-inline-signed", "cleartext [Good]"),
    ("gpgdeb-pgpmime-enc-only", "decrypt SeipdV1 []"),
    ("gpgdeb-pgpmime-enc-signed", "decrypt SeipdV1 [Good]"),
    ("gpgdeb-pgpmime-ocb", "decrypt Ocbed [Good]"),
    ("gpgdeb-pgpmime-passphrase-key", "decrypt SeipdV1 [Good]"),
    ("gpgdeb-pgpmime-protected-headers", "decrypt SeipdV1 [Good]"),
    ("gpgdeb-pgpmime-rsa-attach", "decrypt SeipdV1 [Good]"),
    ("gpgdeb-pgpmime-signed-rsa", "detached [Good]"),
    ("gpgdeb-pgpmime-signed-sha1", "detached [WeakHash]"),
    ("gpgdeb-pgpmime-signed", "detached [Good]"),
    ("gpgdeb-pgpmime-to-rnp", "decrypt SeipdV1 [Good]"),
    ("gpgdeb-pgpmime-to-sq-v4", "decrypt SeipdV1 [Good]"),
    ("gpgdeb-sigspoof-filename", "decrypt SeipdV1 [Good]"),
    ("rnp-pgpmime-enc-signed", "decrypt SeipdV1 [Good]"),
    ("rnp-pgpmime-signed", "detached [Good]"),
    ("spoof-cleartext-hash-header", "cleartext [Good]"),
    ("spoof-enc-signed-by-other", "decrypt SeipdV1 [Good]"),
    ("spoof-from-mismatch", "detached [Good]"),
    ("spoof-html-badge", "none"),
    ("spoof-inline-partial", "cleartext [Good]"),
    ("spoof-mime-wrap-forwarded", "detached [Good]"),
    ("spoof-mime-wrap-prefix", "detached [Good]"),
    ("spoof-unknown-key", "detached [UnknownKey]"),
    ("spoof-wrong-content", "detached [Bad]"),
    ("sq-v4-pgpmime-enc-signed", "decrypt SeipdV2 [Good]"),
    ("sq-v6-pgpmime-enc-signed", "decrypt SeipdV2 [Good]"),
    ("sq-v6-pgpmime-signed", "detached [Good]"),
    ("sq-v6v4-pgpmime-enc-signed", "decrypt SeipdV2 [Good]"),
];

fn sigs(v: &[SignatureVerdict]) -> String {
    let s: Vec<String> = v.iter().map(|v| format!("{:?}", v.status)).collect();
    format!("[{}]", s.join(","))
}

/// The first part of the `multipart/signed` entity (CRLF, as signed) and its boundary.
fn signed_part(text: &str) -> Option<&str> {
    let ct = text.find("protocol=\"application/pgp-signature\"")?;
    let line = &text[ct..ct + text[ct..].find('\n')?];
    let b = line.find("boundary=\"")? + "boundary=\"".len();
    let boundary = &line[b..b + line[b..].find('"')?];
    let open = format!("--{boundary}\r\n");
    let start = ct + text[ct..].find(&open)? + open.len();
    let end = start + text[start..].find(&format!("\r\n--{boundary}"))?;
    Some(&text[start..end])
}

fn outcome(text: &str, keys: &[SecretKey<'_>], certs: &[Vec<u8>]) -> String {
    if let Some(part) = signed_part(text) {
        let sig = armored_in(text, "PGP SIGNATURE").expect("signature part");
        return match keyless::verify_detached(part.as_bytes(), &sig, certs) {
            Ok(v) => format!("detached {}", sigs(&[v])),
            Err(r) => format!("detached {:?}", r.reason),
        };
    }
    if let Some(block) = armored_in(text, "PGP SIGNED MESSAGE") {
        return match keyless::verify_cleartext(&block, certs) {
            Ok(v) => format!("cleartext {}", sigs(&v.signatures)),
            Err(r) => format!("cleartext {:?}", r.reason),
        };
    }
    let Some(msg) = armored_in(text, "PGP MESSAGE") else {
        return "none".into();
    };
    let sk = match keyed::unwrap(&msg, keys) {
        Ok(sk) => sk,
        Err(r) => return format!("unwrap {:?}", r.reason),
    };
    match keyless::decrypt(&msg, &sk, certs) {
        Ok(d) => format!("decrypt {:?} {}", d.container, sigs(&d.signatures)),
        Err(r) => format!("decrypt {:?}", r.reason),
    }
}

#[test]
fn corpus_outcomes() {
    let secret: Vec<(Vec<u8>, Option<&str>)> =
        SECRET_KEYS.iter().map(|(k, p)| (key(k), *p)).collect();
    let keys: Vec<SecretKey<'_>> = secret
        .iter()
        .map(|(k, p)| SecretKey {
            key: k,
            passphrase: p.map(str::as_bytes),
        })
        .collect();
    let certs = certs();
    let mut names: Vec<String> = std::fs::read_dir(common::corpus().join("eml"))
        .expect("eml dir")
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    let mut got = vec![];
    for n in &names {
        let text = String::from_utf8(read(&format!("eml/{n}"))).unwrap();
        got.push((
            n.trim_end_matches(".eml").to_string(),
            outcome(&text, &keys, &certs),
        ));
    }
    let want: Vec<(String, String)> = EXPECTED
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
    if got != want {
        for (n, o) in &got {
            println!("    (\"{n}\", \"{o}\"),");
        }
        panic!("corpus outcomes differ from EXPECTED (actual table above)");
    }
}
