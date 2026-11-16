//! The send side: detached and inline signing, key generation (with its revocation certificate), key renewal and
//! encryption, each read back through the receive side, plus fixed vectors cross-checked with GnuPG
//! (tests/corpus/send/README.txt): signatures of corpus keys are byte-identical to the stored ones that `gpg --verify`
//! accepted, and GnuPG's message to and signature by a generated key decrypt and verify here.
mod common;

use common::{certs, key, read};
use pgpsplit::{Container, GeneratedKey, Reason, SecretKey, SigStatus, SignMode, keyed, keyless};

/// 2026-11-16T00:00:00Z: after every corpus key was made.
const NOW: u32 = 1_794_787_200;
const DATA: &[u8] = b"Content-Type: text/plain; charset=utf-8\r\n\r\nHello from the send side.\r\n";

fn sk(k: &[u8]) -> SecretKey<'_> {
    SecretKey {
        key: k,
        passphrase: None,
    }
}

fn fpr(cert: &[u8]) -> Vec<u8> {
    keyless::cert_info(cert).unwrap().fingerprint
}

const THREE_YEARS: u32 = 94_608_000;

fn generated(uids: &[&str], lifetime: Option<u32>) -> pgpsplit::KeyPair {
    generate(uids, lifetime).key
}

fn generate(uids: &[&str], lifetime: Option<u32>) -> GeneratedKey {
    keyed::generate_key(uids, NOW, lifetime).unwrap_or_else(|r| panic!("generate: {r}"))
}

/// The payload of a signing that must succeed.
fn sign(k: SecretKey<'_>, data: &[u8], mode: SignMode, r: &[&[u8]], at: u32) -> Vec<u8> {
    keyed::sign(k, data, mode, r, at)
        .unwrap_or_else(|r| panic!("sign: {r}"))
        .payload
}

/// Unwrap with `secret`, then decrypt with `certs` for the signatures.
fn open(message: &[u8], secret: &[u8], certs: &[Vec<u8>]) -> pgpsplit::Decrypted {
    let session_key =
        keyed::unwrap(message, &[sk(secret)]).unwrap_or_else(|r| panic!("unwrap: {r}"));
    keyless::decrypt(message, &session_key, certs).unwrap_or_else(|r| panic!("decrypt: {r}"))
}

#[test]
fn detached_signature_verifies_and_is_deterministic() {
    for name in ["gpgdeb-dana", "gpgdeb-rex", "rnp-tim", "sq-v4"] {
        let secret = key(&format!("{name}.sec.asc"));
        let cert = key(&format!("{name}.pub.asc"));
        let sig = sign(sk(&secret), DATA, SignMode::Detached, &[], NOW);
        assert!(sig.starts_with(b"-----BEGIN PGP SIGNATURE-----"), "{name}");
        let again = sign(sk(&secret), DATA, SignMode::Detached, &[], NOW);
        assert_eq!(
            sig, again,
            "{name}: v4 signatures are a function of their inputs"
        );
        let v = keyless::verify_detached(DATA, &sig, &[&cert]).unwrap();
        assert_eq!(v.status, SigStatus::Good, "{name}");
        assert_eq!(v.created, Some(NOW));
        assert!(v.hash_alg.unwrap() >= 8, "{name}: SHA-256 or stronger");
        assert_eq!(v.signer.unwrap().cert, fpr(&cert));
        // One changed byte fails.
        let mut other = DATA.to_vec();
        other[0] ^= 1;
        let v = keyless::verify_detached(&other, &sig, &[&cert]).unwrap();
        assert_eq!(v.status, SigStatus::Bad, "{name}");
    }
}

#[test]
fn v6_signatures_verify_with_a_fresh_salt() {
    let secret = key("sq-v6.sec.asc");
    let cert = key("sq-v6.pub.asc");
    let a = sign(sk(&secret), DATA, SignMode::Detached, &[], NOW);
    let b = sign(sk(&secret), DATA, SignMode::Detached, &[], NOW);
    assert_ne!(a, b, "RFC 9580 v6 signatures are salted");
    for s in [a, b] {
        let v = keyless::verify_detached(DATA, &s, &[&cert]).unwrap();
        assert_eq!(v.status, SigStatus::Good);
    }
}

#[test]
fn inline_signature_carries_the_intended_recipients() {
    let secret = key("gpgdeb-dana.sec.asc");
    let cert = key("gpgdeb-dana.pub.asc");
    let rcpts = [fpr(&key("gpgdeb-pat.pub.asc")), fpr(&key("sq-v6.pub.asc"))];
    let r: Vec<&[u8]> = rcpts.iter().map(Vec::as_slice).collect();
    let msg = sign(sk(&secret), DATA, SignMode::Inline, &r, NOW);
    assert_eq!(msg[0] & 0x3f, 4, "starts with a one-pass signature packet");
    assert_eq!(msg, sign(sk(&secret), DATA, SignMode::Inline, &r, NOW));
    let v = keyless::verify_message(&msg, &[&cert]).unwrap();
    assert_eq!(v.payload, DATA);
    assert_eq!(v.signatures.len(), 1);
    assert_eq!(v.signatures[0].status, SigStatus::Good);
    assert_eq!(v.signatures[0].intended_recipients, rcpts);
}

#[test]
fn signing_refusals() {
    let pat = key("gpgdeb-pat.sec.asc");
    let protected = |pw: &'static [u8]| SecretKey {
        key: &pat,
        passphrase: Some(pw),
    };
    let r = keyed::sign(protected(b"wrong"), DATA, SignMode::Detached, &[], NOW).unwrap_err();
    assert_eq!(r.reason, Reason::BadPassphrase);
    let r = keyed::sign(protected(b"wrong"), DATA, SignMode::Inline, &[], NOW).unwrap_err();
    assert_eq!(r.reason, Reason::BadPassphrase);
    let sig = sign(
        protected(b"correct horse"),
        DATA,
        SignMode::Detached,
        &[],
        NOW,
    );
    let v = keyless::verify_detached(DATA, &sig, &[key("gpgdeb-pat.pub.asc")]).unwrap();
    assert_eq!(v.status, SigStatus::Good);

    let dana = key("gpgdeb-dana.sec.asc");
    // Before the key existed: no valid signing key at that time.
    let r = keyed::sign(sk(&dana), DATA, SignMode::Detached, &[], 1).unwrap_err();
    assert_eq!(r.reason, Reason::BadKey);
    let r = keyed::sign(sk(&dana), DATA, SignMode::Inline, &[&[1, 2, 3]], NOW).unwrap_err();
    assert_eq!(r.reason, Reason::InvalidRequest);
    let r = keyed::sign(sk(b"not a key"), DATA, SignMode::Detached, &[], NOW).unwrap_err();
    assert_eq!(r.reason, Reason::BadKey);
    // An expired key no longer signs.
    let k = generated(&["Exp <exp@example.test>"], Some(60));
    let r = keyed::sign(
        sk(&k.unprotected_key),
        DATA,
        SignMode::Detached,
        &[],
        NOW + 60,
    )
    .unwrap_err();
    assert_eq!(r.reason, Reason::BadKey);
    sign(
        sk(&k.unprotected_key),
        DATA,
        SignMode::Detached,
        &[],
        NOW + 59,
    );
}

#[test]
fn generated_key_has_the_profile() {
    let k = generated(
        &["Ann Example <ann@example.test>", "Ann <ann@work.test>"],
        None,
    );
    let i = &k.info;
    assert_eq!(i.version, 4);
    assert!(!i.revoked);
    assert_eq!(
        i.uids,
        ["Ann Example <ann@example.test>", "Ann <ann@work.test>"]
    );
    assert_eq!(i.keys.len(), 2);
    let (p, s) = (&i.keys[0], &i.keys[1]);
    assert!(p.valid && p.sign && !p.encrypt && p.expires.is_none());
    assert!(s.valid && !s.sign && s.encrypt && s.expires.is_none());
    assert_eq!(keyless::cert_info(&k.public_cert).unwrap(), k.info);
    // Unprotected, canonical: import gives the same bytes back.
    let again = keyed::import_key(sk(&k.unprotected_key)).unwrap();
    assert_eq!(again.unprotected_key, k.unprotected_key);
    assert_eq!(again.public_cert, k.public_cert);
    // Fresh key material every time.
    assert_ne!(
        generated(&["a <a@example.test>"], None).info.fingerprint,
        i.fingerprint
    );

    let e = generated(&["E <e@example.test>"], Some(THREE_YEARS));
    assert!(
        e.info
            .keys
            .iter()
            .all(|k| k.expires == Some(NOW + THREE_YEARS))
    );

    for (uids, validity) in [(&[][..], None), (&[""][..], None), (&["x"][..], Some(0))] {
        let r = keyed::generate_key(uids, NOW, validity).err().unwrap();
        assert_eq!(r.reason, Reason::InvalidRequest);
    }
}

#[test]
fn generated_key_signs_and_receives() {
    let k = generated(&["Bo <bo@example.test>"], None);
    let sig = sign(sk(&k.unprotected_key), DATA, SignMode::Detached, &[], NOW);
    let v = keyless::verify_detached(DATA, &sig, &[&k.public_cert]).unwrap();
    assert_eq!(v.status, SigStatus::Good);
    assert_eq!(v.signer.unwrap().uids, ["Bo <bo@example.test>"]);
    let msg = keyless::encrypt(DATA, &[&k.public_cert], false, NOW).unwrap();
    let d = open(&msg, &k.unprotected_key, &[]);
    assert_eq!(d.payload, DATA);
    assert_eq!(d.container, Container::SeipdV1);
}

#[test]
fn encrypt_round_trips_to_every_recipient() {
    let dana = key("gpgdeb-dana.pub.asc");
    let v6 = key("sq-v6.pub.asc");
    let rex = key("gpgdeb-rex.pub.asc");
    let msg = keyless::encrypt(DATA, &[&dana, &v6, &rex], false, NOW).unwrap();
    assert!(msg.starts_with(b"-----BEGIN PGP MESSAGE-----"));
    assert_ne!(
        msg,
        keyless::encrypt(DATA, &[&dana, &v6, &rex], false, NOW).unwrap()
    );
    for name in ["gpgdeb-dana", "sq-v6", "gpgdeb-rex"] {
        let d = open(&msg, &key(&format!("{name}.sec.asc")), &[]);
        assert_eq!(d.payload, DATA, "{name}");
        assert_eq!(d.container, Container::SeipdV1, "mixed v4/v6: SEIPD v1");
        assert!(d.signatures.is_empty());
    }
    // Only v6 recipients: SEIPD v2.
    let msg = keyless::encrypt(DATA, &[&v6], false, NOW).unwrap();
    let d = open(&msg, &key("sq-v6.sec.asc"), &[]);
    assert_eq!(
        (d.container, d.payload.as_slice()),
        (Container::SeipdV2, DATA)
    );
}

#[test]
fn sign_then_encrypt_combined() {
    let dana = key("gpgdeb-dana.sec.asc");
    let dana_cert = key("gpgdeb-dana.pub.asc");
    let pat = key("gpgdeb-pat.pub.asc");
    let rcpts = [fpr(&pat), fpr(&dana_cert)];
    let r: Vec<&[u8]> = rcpts.iter().map(Vec::as_slice).collect();
    let signed = sign(sk(&dana), DATA, SignMode::Inline, &r, NOW);
    let msg = keyless::encrypt(&signed, &[&pat, &dana_cert], true, NOW).unwrap();
    let pat_key = keyed::import_key(SecretKey {
        key: &key("gpgdeb-pat.sec.asc"),
        passphrase: Some(b"correct horse"),
    })
    .unwrap();
    let d = open(&msg, &pat_key.unprotected_key, &certs());
    assert_eq!(d.payload, DATA);
    assert_eq!(d.signatures.len(), 1);
    assert_eq!(d.signatures[0].status, SigStatus::Good);
    assert_eq!(d.signatures[0].intended_recipients, rcpts);
}

#[test]
fn encrypt_refusals() {
    let dana = key("gpgdeb-dana.pub.asc");
    let r = keyless::encrypt(DATA, &[&dana[..], &b"not a cert"[..]], false, NOW).unwrap_err();
    assert_eq!(r.reason, Reason::BadKey);
    assert!(r.detail.contains("certificate 1"), "{}", r.detail);
    let none: &[&[u8]] = &[];
    assert_eq!(
        keyless::encrypt(DATA, none, false, NOW).unwrap_err().reason,
        Reason::InvalidRequest
    );
    // Expired at `now`: refused, the detail names the certificate.
    let k = generated(&["Old <old@example.test>"], Some(60));
    let r = keyless::encrypt(DATA, &[&k.public_cert], false, NOW + 60).unwrap_err();
    assert_eq!(r.reason, Reason::BadKey);
    let hex: String = k
        .info
        .fingerprint
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    assert!(r.detail.contains(&hex), "{}", r.detail);
    keyless::encrypt(DATA, &[&k.public_cert], false, NOW + 59).unwrap();
    // data_is_message takes only a signed or literal message.
    for bad in [&b"plain text"[..], &read("bzip2-dana.pgp")] {
        let r = keyless::encrypt(bad, &[&dana], true, NOW).unwrap_err();
        assert_eq!(r.reason, Reason::InvalidRequest);
    }
}

#[test]
fn sign_reports_its_hash() {
    let dana = key("gpgdeb-dana.sec.asc");
    let s = keyed::sign(sk(&dana), DATA, SignMode::Detached, &[], NOW).unwrap();
    assert_eq!(s.hash_alg, 8, "SHA-256");
    let v = keyless::verify_detached(DATA, &s.payload, &[key("gpgdeb-dana.pub.asc")]).unwrap();
    assert_eq!(v.hash_alg, Some(s.hash_alg));
}

/// The packets of an armored block.
fn packets(armored: &[u8]) -> Vec<pgp::packet::Packet> {
    let mut bin = Vec::new();
    std::io::Read::read_to_end(
        &mut pgp::armor::Dearmor::new(std::io::BufReader::new(armored)),
        &mut bin,
    )
    .unwrap();
    pgp::packet::PacketParser::new(std::io::BufReader::new(&bin[..]))
        .map(Result::unwrap)
        .collect()
}

/// The revocation certificate is the primary key and a valid key revocation signature over it.
#[test]
fn generated_revocation_certificate_revokes() {
    use pgp::composed::{Deserializable, SignedPublicKey};
    use pgp::packet::{Packet, SignatureType};

    let g = generate(&["Rev <rev@example.test>"], Some(THREE_YEARS));
    assert!(
        g.revocation
            .starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----")
    );
    let cert = SignedPublicKey::from_bytes(&g.key.public_cert[..]).unwrap();
    let packets = packets(&g.revocation);
    assert_eq!(packets.len(), 2);
    let Packet::PublicKey(ref primary) = packets[0] else {
        panic!("first packet is not the primary key")
    };
    assert_eq!(primary, &cert.primary_key);
    let Packet::Signature(ref sig) = packets[1] else {
        panic!("second packet is not a signature")
    };
    assert_eq!(sig.typ(), Some(SignatureType::KeyRevocation));
    sig.verify_key(&cert.primary_key).unwrap();
    // Merged into the certificate, it revokes it.
    let mut revoked = cert.clone();
    revoked.details.revocation_signatures.push(sig.clone());
    let bin = pgp::ser::Serialize::to_bytes(&revoked).unwrap();
    assert!(keyless::cert_info(&bin).unwrap().revoked);
    let r = keyless::encrypt(DATA, &[&bin], false, NOW).unwrap_err();
    assert_eq!(r.reason, Reason::BadKey);
}

#[test]
fn extend_expiry_moves_the_expiry_forward() {
    let g = generated(
        &["Ren <ren@example.test>", "Ren 2 <ren@two.test>"],
        Some(THREE_YEARS),
    );
    let later = NOW + THREE_YEARS - 60 * 86400;
    let r = keyed::extend_expiry(sk(&g.unprotected_key), later, Some(THREE_YEARS)).unwrap();
    assert_eq!(r.info.fingerprint, g.info.fingerprint);
    assert_eq!(r.info.uids, g.info.uids);
    assert!(
        r.info
            .keys
            .iter()
            .all(|k| k.valid && k.expires == Some(later + THREE_YEARS))
    );
    assert_eq!(keyless::cert_info(&r.public_cert).unwrap(), r.info);
    // Past the old expiry the renewed key still signs and receives; the old certificate does not.
    let after = NOW + THREE_YEARS + 86400;
    assert_eq!(
        keyless::encrypt(DATA, &[&g.public_cert], false, after)
            .unwrap_err()
            .reason,
        Reason::BadKey
    );
    let msg = keyless::encrypt(DATA, &[&r.public_cert], false, after).unwrap();
    assert_eq!(open(&msg, &r.secret_key, &[]).payload, DATA);
    let sig = sign(sk(&r.secret_key), DATA, SignMode::Detached, &[], after);
    let v = keyless::verify_detached(DATA, &sig, &[&r.public_cert]).unwrap();
    assert_eq!(v.status, SigStatus::Good);
    // One self-signature per User ID and one binding: the superseded ones are dropped.
    let cert = <pgp::composed::SignedPublicKey as pgp::composed::Deserializable>::from_bytes(
        &r.public_cert[..],
    )
    .unwrap();
    assert!(cert.details.users.iter().all(|u| u.signatures.len() == 1));
    assert!(cert.public_subkeys.iter().all(|s| s.signatures.len() == 1));
    // Lifetime None removes the expiry.
    let n = keyed::extend_expiry(sk(&r.secret_key), after, None).unwrap();
    assert!(n.info.keys.iter().all(|k| k.expires.is_none()));
}

#[test]
fn extend_expiry_keeps_protection_and_renews_signing_subkeys() {
    // GnuPG's passphrase-protected key: wrong passphrase refused, right one renews and the key stays protected.
    let pat = key("gpgdeb-pat.sec.asc");
    let r = keyed::extend_expiry(
        SecretKey {
            key: &pat,
            passphrase: Some(b"wrong"),
        },
        NOW,
        Some(THREE_YEARS),
    )
    .err()
    .unwrap();
    assert_eq!(r.reason, Reason::BadPassphrase);
    let renewed = keyed::extend_expiry(
        SecretKey {
            key: &pat,
            passphrase: Some(b"correct horse"),
        },
        NOW,
        Some(THREE_YEARS),
    )
    .unwrap();
    assert!(
        renewed
            .info
            .keys
            .iter()
            .all(|k| k.expires == Some(NOW + THREE_YEARS))
    );
    assert_eq!(
        keyed::sign(sk(&renewed.secret_key), DATA, SignMode::Detached, &[], NOW)
            .unwrap_err()
            .reason,
        Reason::BadPassphrase,
        "still protected"
    );
    // sq's v4 key has signing, authentication and encryption subkeys: every binding is renewed and the signing
    // subkey keeps a valid back-signature (it still signs, as the subkey).
    let sq = key("sq-v4.sec.asc");
    let before = keyless::cert_info(&key("sq-v4.pub.asc")).unwrap();
    let r = keyed::extend_expiry(sk(&sq), NOW, Some(THREE_YEARS)).unwrap();
    assert_eq!(before.keys.len(), r.info.keys.len());
    for (a, b) in before.keys.iter().zip(&r.info.keys) {
        assert_eq!((a.sign, a.encrypt, a.valid), (b.sign, b.encrypt, b.valid));
        assert_eq!(b.expires, Some(NOW + THREE_YEARS));
    }
    let sig = sign(sk(&r.secret_key), DATA, SignMode::Detached, &[], NOW);
    let v = keyless::verify_detached(DATA, &sig, &[&r.public_cert]).unwrap();
    assert_eq!(v.status, SigStatus::Good);
    let signer = v.signer.unwrap();
    assert_ne!(signer.key, signer.cert, "signed by the subkey");
    // v6 keys are not renewed here.
    let v6 = key("sq-v6.sec.asc");
    assert_eq!(
        keyed::extend_expiry(sk(&v6), NOW, Some(1))
            .err()
            .unwrap()
            .reason,
        Reason::Unsupported
    );
}

#[test]
fn a_revoked_key_is_not_renewed() {
    use pgp::composed::{Deserializable, SignedSecretKey};
    let g = generate(&["Gone <gone@example.test>"], Some(THREE_YEARS));
    let pgp::packet::Packet::Signature(ref sig) = packets(&g.revocation)[1] else {
        panic!("no revocation signature")
    };
    let mut secret = SignedSecretKey::from_bytes(&g.key.unprotected_key[..]).unwrap();
    secret.details.revocation_signatures.push(sig.clone());
    let bin = pgp::ser::Serialize::to_bytes(&secret).unwrap();
    let r = keyed::extend_expiry(sk(&bin), NOW + 86400, Some(THREE_YEARS))
        .err()
        .unwrap();
    assert_eq!(r.reason, Reason::BadKey);
}

/// tests/corpus/send: the stored signatures GnuPG verified are made again byte for byte, and GnuPG's message to and
/// signature by a generated key decrypt and verify here.
#[test]
fn gnupg_vectors() {
    let data = read("send/data.txt");
    let dana = key("gpgdeb-dana.sec.asc");
    let rex = key("gpgdeb-rex.sec.asc");
    let pat = fpr(&key("gpgdeb-pat.pub.asc"));
    assert_eq!(
        sign(sk(&dana), &data, SignMode::Detached, &[], NOW),
        read("send/dana-detached.asc")
    );
    assert_eq!(
        sign(sk(&rex), &data, SignMode::Detached, &[], NOW),
        read("send/rex-detached.asc")
    );
    assert_eq!(
        sign(sk(&dana), &data, SignMode::Inline, &[&pat], NOW),
        read("send/dana-inline.pgp")
    );

    let secret = read("send/generated.sec.pgp");
    let cert = read("send/generated.pub.pgp");
    let info = keyless::cert_info(&cert).unwrap();
    assert_eq!(info.uids, ["Vec Tor <vector@example.test>"]);
    assert!(
        info.keys
            .iter()
            .all(|k| k.expires == Some(NOW + THREE_YEARS))
    );
    let d = open(
        &read("send/gnupg-to-generated.asc"),
        &secret,
        &[key("gpgdeb-dana.pub.asc")],
    );
    assert_eq!(d.payload, data);
    assert_eq!(d.signatures[0].status, SigStatus::Good);
    let v =
        keyless::verify_detached(&data, &read("send/gnupg-by-generated.asc"), &[&cert]).unwrap();
    assert_eq!(v.status, SigStatus::Good);
    assert_eq!(v.signer.unwrap().cert, info.fingerprint);
}
