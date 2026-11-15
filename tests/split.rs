//! The split flow and its refusals on real fixtures: keyed unwrap then keyless decrypt verifies a GnuPG message; SED
//! is refused before any key is parsed; tampered SEIPD releases nothing; 64 MiB decompression bombs (ZLIB, BZip2) are
//! refused; BZip2 decrypts; key import removes the passphrase and repairs GnuPG's non-minimal secret MPIs.
mod common;

use common::{armored, certs, key, read};
use pgpsplit::{Container, Reason, SecretKey, SessionKey, SigStatus, keyed, keyless};

const NO_CERTS: &[&[u8]] = &[];

fn dana() -> Vec<u8> {
    key("gpgdeb-dana.sec.asc")
}

fn unwrap_with(message: &[u8], k: &[u8]) -> SessionKey {
    keyed::unwrap(
        message,
        &[SecretKey {
            key: k,
            passphrase: None,
        }],
    )
    .unwrap_or_else(|r| panic!("unwrap: {r}"))
}

#[test]
fn split_decrypt_verifies() {
    let data = armored("eml/gpgdeb-pgpmime-enc-signed.eml");
    let sk = unwrap_with(&data, &dana());
    let d = keyless::decrypt(&data, &sk, &[key("gpgdeb-dana.pub.asc")]).unwrap();
    assert!(!d.payload.is_empty());
    assert_eq!(d.pkesk_count, 1);
    assert_eq!(d.signatures.len(), 1);
    let v = &d.signatures[0];
    assert_eq!(v.status, SigStatus::Good);
    let signer = v.signer.as_ref().unwrap();
    assert!(signer.uids.iter().any(|u| u.contains("dana@gpgdeb.test")));
    assert_eq!(v.issuer, signer.key);

    // Without the signer's cert the plaintext is the same and the signature is unknown.
    let d2 = keyless::decrypt(&data, &sk, NO_CERTS).unwrap();
    assert_eq!(d2.payload, d.payload);
    assert_eq!(d2.signatures[0].status, SigStatus::UnknownKey);
    assert!(d2.signatures[0].signer.is_none());
}

/// The literal-data file name ("[GNUPG:] GOODSIG ...") is never part of what decrypt returns.
#[test]
fn literal_file_name_is_not_returned() {
    let data = armored("eml/gpgdeb-sigspoof-filename.eml");
    let sk = unwrap_with(&data, &dana());
    let d = keyless::decrypt(&data, &sk, &certs()).unwrap();
    assert!(!d.payload.is_empty());
    assert!(!d.payload.windows(7).any(|w| w == b"GOODSIG"));
}

#[test]
fn unwrap_needs_a_matching_key() {
    let data = armored("eml/gpgdeb-pgpmime-enc-signed.eml");
    let r = keyed::unwrap(&data, &[]).err().unwrap();
    assert_eq!(r.reason, Reason::NoKey);
    let other = key("sq-v4.sec.asc");
    let r = keyed::unwrap(
        &data,
        &[SecretKey {
            key: &other,
            passphrase: None,
        }],
    )
    .err()
    .unwrap();
    assert_eq!(r.reason, Reason::NoKey);
    // A key that does not parse is skipped when another one does.
    let dana = dana();
    let keys = [
        SecretKey {
            key: b"not a key",
            passphrase: None,
        },
        SecretKey {
            key: &dana,
            passphrase: None,
        },
    ];
    assert!(keyed::unwrap(&data, &keys).is_ok());
    let r = keyed::unwrap(&data, &keys[..1]).err().unwrap();
    assert_eq!(r.reason, Reason::BadKey);
}

#[test]
fn sed_is_refused_before_the_key() {
    let sed = armored("eml/efail-pgp-mdc-stripped.eml");
    // The key is never parsed: a garbage key still yields NoIntegrity, not BadKey.
    let r = keyed::unwrap(
        &sed,
        &[SecretKey {
            key: b"garbage",
            passphrase: None,
        }],
    )
    .err()
    .unwrap();
    assert_eq!(r.reason, Reason::NoIntegrity, "{r}");
    let r = keyless::decrypt(
        &sed,
        &SessionKey::V3 {
            sym_alg: 9,
            key: vec![0; 32],
        },
        NO_CERTS,
    )
    .err()
    .unwrap();
    assert_eq!(r.reason, Reason::NoIntegrity, "{r}");
}

#[test]
fn tampered_seipd_releases_nothing() {
    let data = armored("eml/efail-pgp-mdc-tampered.eml");
    let sk = unwrap_with(&data, &dana());
    let r = keyless::decrypt(&data, &sk, NO_CERTS).err().unwrap();
    assert_eq!(r.reason, Reason::IntegrityFailure, "{r}");
}

#[test]
fn decompression_bombs_are_bounded() {
    for bomb in ["bomb-64mib.pgp", "bomb-bzip2-80mib.pgp"] {
        let r = keyless::verify_message(&read(bomb), NO_CERTS)
            .err()
            .unwrap();
        assert_eq!(r.reason, Reason::TooLarge, "{bomb}: {r}");
    }
}

/// BZip2 (older PGP): an encrypted BZip2 message decrypts.
#[test]
fn bzip2_decrypts() {
    let data = read("bzip2-dana.pgp");
    let sk = unwrap_with(&data, &dana());
    let d = keyless::decrypt(&data, &sk, NO_CERTS).unwrap();
    assert_eq!(d.payload, b"BZip2 interop test: hello from older PGP.\n");
    assert_eq!(d.container, Container::SeipdV1);
}

#[test]
fn bad_inputs_are_refused_with_their_reason() {
    let enc = armored("eml/gpgdeb-pgpmime-enc-signed.eml");
    let r = keyless::verify_message(&enc, NO_CERTS).err().unwrap();
    assert_eq!(r.reason, Reason::InvalidRequest);
    let r = keyless::decrypt(&enc, &SessionKey::V6 { key: vec![] }, NO_CERTS)
        .err()
        .unwrap();
    assert_eq!(r.reason, Reason::InvalidRequest);
    let wrong = SessionKey::V3 {
        sym_alg: 9,
        key: vec![1; 32],
    };
    let r = keyless::decrypt(&enc, &wrong, NO_CERTS).err().unwrap();
    assert!(
        matches!(r.reason, Reason::DecryptFailed | Reason::IntegrityFailure),
        "{r}"
    );
    let signed = common::armored_in(
        &String::from_utf8(read("eml/gpgdeb-inline-signed.eml")).unwrap(),
        "PGP SIGNED MESSAGE",
    )
    .unwrap();
    let r = keyless::decrypt(&signed, &wrong, NO_CERTS).err().unwrap();
    assert_eq!(r.reason, Reason::Malformed, "{r}");
    assert_eq!(
        keyless::verify_cleartext(&[0xff, 0xfe], NO_CERTS)
            .err()
            .unwrap()
            .reason,
        Reason::Malformed
    );
    assert_eq!(
        keyless::verify_detached(b"data", b"not a signature", NO_CERTS)
            .err()
            .unwrap()
            .reason,
        Reason::Malformed
    );
    assert!(keyless::cert_info(b"not a cert").is_none());
}

#[test]
fn import_removes_the_passphrase() {
    let pat = key("gpgdeb-pat.sec.asc");
    let r = keyed::import_key(SecretKey {
        key: &pat,
        passphrase: Some(b"wrong"),
    })
    .err()
    .unwrap();
    assert_eq!(r.reason, Reason::BadPassphrase);
    let imported = keyed::import_key(SecretKey {
        key: &pat,
        passphrase: Some(b"correct horse"),
    })
    .unwrap();
    assert_eq!(
        keyless::cert_info(&imported.public_cert).as_ref(),
        Some(&imported.info)
    );
    assert_eq!(
        keyless::cert_info(&key("gpgdeb-pat.pub.asc"))
            .unwrap()
            .fingerprint,
        imported.info.fingerprint
    );
    // The unprotected key unwraps without a passphrase.
    let data = armored("eml/gpgdeb-pgpmime-passphrase-key.eml");
    let sk = unwrap_with(&data, &imported.unprotected_key);
    let d = keyless::decrypt(&data, &sk, &certs()).unwrap();
    assert!(!d.payload.is_empty());
}

/// GnuPG exported this Ed25519 key with a non-minimal secret MPI (keys/gnupg-zed.README); rPGP alone refuses it.
#[test]
fn non_minimal_mpi_key_imports_and_decrypts() {
    let zed = key("gnupg-zed.sec.asc");
    let imported = keyed::import_key(SecretKey {
        key: &zed,
        passphrase: None,
    })
    .unwrap();
    assert!(imported.info.keys.iter().all(|k| k.valid));
    let data = armored("eml/gnupg-nonminimal-mpi-key.eml");
    for k in [&zed, &imported.unprotected_key] {
        let sk = unwrap_with(&data, k);
        let d = keyless::decrypt(&data, &sk, &[key("gnupg-zed.pub.asc")]).unwrap();
        assert_eq!(d.signatures[0].status, SigStatus::Good);
    }
}

#[test]
fn cert_info_reports_keys_and_capabilities() {
    let info = keyless::cert_info(&key("sq-v6.pub.asc")).unwrap();
    assert_eq!(info.version, 6);
    assert_eq!(info.fingerprint.len(), 32);
    assert_eq!(info.keys[0].fingerprint, info.fingerprint);
    assert!(info.keys.iter().all(|k| k.valid && !k.revoked));
    assert!(info.keys.iter().any(|k| k.sign));
    assert!(info.keys.iter().any(|k| k.encrypt));
    let v4 = keyless::cert_info(&key("gpgdeb-dana.pub.asc")).unwrap();
    assert_eq!(v4.version, 4);
    assert_eq!(v4.fingerprint.len(), 20);
    assert_eq!(
        v4.uids,
        vec!["Dana (gpgdeb default) <dana@gpgdeb.test>".to_string()]
    );
}

/// The discriminants are part of the API: wire formats carry them as integers.
#[test]
fn discriminants_are_stable() {
    use Reason::*;
    let reasons = [
        InvalidRequest,
        Malformed,
        NotEncrypted,
        NoIntegrity,
        IntegrityFailure,
        NoKey,
        BadPassphrase,
        BadKey,
        TooLarge,
        Unsupported,
        DecryptFailed,
    ];
    for (i, r) in reasons.iter().enumerate() {
        assert_eq!(*r as u8 as usize, i + 1);
    }
    use Container as C;
    let containers = [
        C::None,
        C::SeipdV1,
        C::SeipdV2,
        C::Ocbed,
        C::Sed,
        C::Unknown,
    ];
    for (i, c) in containers.iter().enumerate() {
        assert_eq!(*c as u8 as usize, i + 1);
    }
    use SigStatus as S;
    let statuses = [S::Good, S::Bad, S::UnknownKey, S::WeakHash, S::KeyInvalid];
    for (i, s) in statuses.iter().enumerate() {
        assert_eq!(*s as u8 as usize, i + 1);
    }
}
