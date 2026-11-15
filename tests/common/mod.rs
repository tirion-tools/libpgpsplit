//! Fixture access for the integration tests. Corpus: `PGPSPLIT_CORPUS`, else `tests/corpus`.
#![allow(dead_code)]

use std::path::PathBuf;

pub fn corpus() -> PathBuf {
    std::env::var_os("PGPSPLIT_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus"))
}

pub fn read(rel: &str) -> Vec<u8> {
    std::fs::read(corpus().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// The first armored block of `kind` (`"PGP MESSAGE"`, `"PGP SIGNATURE"`, `"PGP SIGNED MESSAGE"`) in `text`, with LF
/// line ends.
pub fn armored_in(text: &str, kind: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {kind}-----");
    let a = text.find(&begin)?;
    // a cleartext-signed block ends with its signature's END line
    let end = if kind == "PGP SIGNED MESSAGE" {
        "-----END PGP SIGNATURE-----".to_string()
    } else {
        format!("-----END {kind}-----")
    };
    let b = a + text[a..].find(&end)? + end.len();
    Some(text[a..b].replace("\r\n", "\n").into_bytes())
}

/// The armored OpenPGP message inside a fixture .eml.
pub fn armored(rel: &str) -> Vec<u8> {
    armored_in(&String::from_utf8(read(rel)).unwrap(), "PGP MESSAGE").expect(rel)
}

/// Secret keys of the corpus profile, with their passphrases.
pub const SECRET_KEYS: &[(&str, Option<&str>)] = &[
    ("gnupg-zed.sec.asc", None),
    ("gpgarch-dana.sec.asc", None),
    ("gpgarch-pat.sec.asc", Some("correct horse")),
    ("gpgarch-rex.sec.asc", None),
    ("gpgdeb-dana.sec.asc", None),
    ("gpgdeb-pat.sec.asc", Some("correct horse")),
    ("gpgdeb-rex.sec.asc", None),
    ("rnp-tim.sec.asc", None),
    ("sq-v4.sec.asc", None),
    ("sq-v6.sec.asc", None),
];

/// Certificates of the corpus profile.
pub const CERTS: &[&str] = &[
    "attacker-mallory.pub.asc",
    "gnupg-zed.pub.asc",
    "gpgarch-dana.pub.asc",
    "gpgarch-pat.pub.asc",
    "gpgarch-rex.pub.asc",
    "gpgdeb-dana.pub.asc",
    "gpgdeb-pat.pub.asc",
    "gpgdeb-rex.pub.asc",
    "rnp-tim.pub.asc",
    "sq-v4.pub.asc",
    "sq-v6.pub.asc",
];

pub fn key(name: &str) -> Vec<u8> {
    read(&format!("keys/{name}"))
}

pub fn certs() -> Vec<Vec<u8>> {
    CERTS.iter().map(|c| key(c)).collect()
}
