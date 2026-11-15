//! Certificate semantics rPGP leaves to the caller: binding validity, key flags, expiry, revocation, and the verdict
//! for one data signature.

use std::io::BufReader;

use proto::v1::crypto::{
    CertInfo, KeyInfo, SignatureVerdict, signature_verdict::Status as SigStatus,
};
use pgp::composed::{Deserializable, SignedPublicKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::packet::{Signature, SignatureType, SubpacketData};
use pgp::types::{Fingerprint, KeyDetails, KeyId, KeyVersion, Tag};

pub const WHY_REVOKED: u32 = 1;
pub const WHY_NO_VALID_BINDING: u32 = 2;
pub const WHY_NOT_SIGNING_CAPABLE: u32 = 4;
pub const WHY_EXPIRED_AT_SIGNING: u32 = 8;
pub const WHY_PREDATES_KEY: u32 = 16;

pub struct KeyEntry {
    pub fpr: Fingerprint,
    pub keyid: KeyId,
    pub can_sign: bool,
    pub can_encrypt: bool,
    pub valid: bool,
    pub revoked: bool,
    pub created: u32,
    pub expires: Option<u32>,
}

pub struct Cert {
    pub cert: SignedPublicKey,
    pub revoked: bool,
    pub uids: Vec<String>,
    pub keys: Vec<KeyEntry>,
}

fn ts(t: pgp::types::Timestamp) -> u32 {
    t.as_secs()
}

fn issued_by_primary(sig: &Signature, primary: &impl KeyDetails) -> bool {
    let fp = primary.fingerprint();
    let id = primary.legacy_key_id();
    let fps = sig.issuer_fingerprint();
    let ids = sig.issuer_key_id();
    (fps.is_empty() && ids.is_empty())
        || fps.iter().any(|f| **f == fp)
        || ids.iter().any(|k| **k == id)
}

pub fn load_cert(bytes: &[u8]) -> Option<Cert> {
    let cert = if crate::ops::is_armored(bytes) {
        SignedPublicKey::from_armor_single(BufReader::new(bytes))
            .ok()?
            .0
    } else {
        SignedPublicKey::from_reader_single(BufReader::new(bytes))
            .ok()?
            .0
    };
    Some(from_public(cert))
}

pub fn from_public(cert: SignedPublicKey) -> Cert {
    let p = &cert.primary_key;
    let pcreated = ts(p.created_at());
    let revoked = cert
        .details
        .revocation_signatures
        .iter()
        .any(|s| s.verify_key(p).is_ok());
    // Self-signatures: direct-key signatures (v6 keys carry flags there) and UID self-certifications.
    let mut flags_sig: Option<&Signature> = None;
    let newer = |a: Option<&Signature>, b: &Signature| match a {
        None => true,
        Some(a) => b.created().map(ts) >= a.created().map(ts),
    };
    for s in &cert.details.direct_signatures {
        if s.verify_key(p).is_ok() && newer(flags_sig, s) {
            flags_sig = Some(s);
        }
    }
    let mut uids = vec![];
    let mut uid_sig: Option<&Signature> = None;
    for u in &cert.details.users {
        let mut ok = false;
        for s in &u.signatures {
            if issued_by_primary(s, p) && s.verify_certification(p, Tag::UserId, &u.id).is_ok() {
                ok = true;
                if s.is_primary() || uid_sig.is_none() {
                    uid_sig = Some(s);
                }
            }
        }
        if ok {
            uids.push(String::from_utf8_lossy(u.id.id()).into_owned());
        }
    }
    let psig = if p.version() == KeyVersion::V6 {
        flags_sig.or(uid_sig)
    } else {
        uid_sig.or(flags_sig)
    };
    let mut keys = vec![KeyEntry {
        fpr: p.fingerprint(),
        keyid: p.legacy_key_id(),
        can_sign: psig.map(|s| s.key_flags().sign()).unwrap_or(false),
        can_encrypt: psig
            .map(|s| {
                let f = s.key_flags();
                f.encrypt_comms() || f.encrypt_storage()
            })
            .unwrap_or(false),
        valid: psig.is_some() && !uids.is_empty()
            || (p.version() == KeyVersion::V6 && flags_sig.is_some()),
        revoked,
        created: pcreated,
        expires: psig
            .and_then(|s| s.key_expiration_time())
            .map(|d| pcreated + d.as_secs()),
    }];
    for sk in &cert.public_subkeys {
        let mut best: Option<&Signature> = None;
        let mut sk_revoked = false;
        for s in &sk.signatures {
            if s.typ() == Some(SignatureType::SubkeyRevocation) {
                if s.verify_subkey_binding(p, &sk.key).is_ok() || s.verify_key(p).is_ok() {
                    sk_revoked = true;
                }
                continue;
            }
            if s.verify_subkey_binding(p, &sk.key).is_err() {
                continue;
            }
            // A signing subkey needs a valid back-signature (primary key binding).
            if s.key_flags().sign() {
                match s.embedded_signature() {
                    Some(b) if b.verify_primary_key_binding(&sk.key, p).is_ok() => {}
                    _ => continue,
                }
            }
            if newer(best, s) {
                best = Some(s);
            }
        }
        let c = ts(sk.key.created_at());
        keys.push(KeyEntry {
            fpr: sk.key.fingerprint(),
            keyid: sk.key.legacy_key_id(),
            can_sign: best.map(|s| s.key_flags().sign()).unwrap_or(false),
            can_encrypt: best
                .map(|s| {
                    let f = s.key_flags();
                    f.encrypt_comms() || f.encrypt_storage()
                })
                .unwrap_or(false),
            valid: best.is_some(),
            revoked: sk_revoked,
            created: c,
            expires: best
                .and_then(|s| s.key_expiration_time())
                .map(|d| c + d.as_secs()),
        });
    }
    Cert {
        cert,
        revoked,
        uids,
        keys,
    }
}

pub fn load_certs(certs: &[Vec<u8>]) -> Vec<Cert> {
    certs.iter().filter_map(|c| load_cert(c)).collect()
}

pub fn info(c: &Cert) -> CertInfo {
    CertInfo {
        valid: true,
        fingerprint: c.keys[0].fpr.as_bytes().to_vec(),
        version: u8::from(c.cert.primary_key.version()) as u32,
        revoked: c.revoked,
        uids: c.uids.clone(),
        keys: c
            .keys
            .iter()
            .map(|k| KeyInfo {
                fingerprint: k.fpr.as_bytes().to_vec(),
                valid: k.valid,
                sign: k.can_sign,
                encrypt: k.can_encrypt,
                revoked: k.revoked,
                expires_unix: k.expires.map(u64::from).unwrap_or(0),
            })
            .collect(),
    }
}

/// Which (cert, key index) issued this signature, by issuer fingerprint first, then key id.
fn find_signer<'c>(certs: &'c [Cert], sig: &Signature) -> Option<(&'c Cert, usize)> {
    for f in sig.issuer_fingerprint() {
        for c in certs {
            if let Some(i) = c.keys.iter().position(|k| k.fpr == *f) {
                return Some((c, i));
            }
        }
    }
    for id in sig.issuer_key_id() {
        for c in certs {
            if let Some(i) = c.keys.iter().position(|k| k.keyid == *id) {
                return Some((c, i));
            }
        }
    }
    None
}

fn weak(h: Option<HashAlgorithm>) -> bool {
    matches!(
        h,
        Some(HashAlgorithm::Md5)
            | Some(HashAlgorithm::Sha1)
            | Some(HashAlgorithm::Ripemd160)
            | None
    )
}

/// Evaluate one data signature. `check` performs the cryptographic verification with the key.
pub fn judge(
    certs: &[Cert],
    sig: &Signature,
    check: &dyn Fn(&Cert, usize) -> bool,
) -> SignatureVerdict {
    let created = sig.created().map(ts).unwrap_or(0);
    let mut v = SignatureVerdict {
        issuer: sig
            .issuer_fingerprint()
            .first()
            .map(|f| f.as_bytes().to_vec())
            .or_else(|| sig.issuer_key_id().first().map(|k| k.as_ref().to_vec()))
            .unwrap_or_default(),
        created_unix: created as u64,
        hash_alg: sig.hash_alg().map(|h| u8::from(h) as u32).unwrap_or(0),
        intended_recipients: sig
            .config()
            .map(|c| {
                c.hashed_subpackets()
                    .filter_map(|p| match &p.data {
                        SubpacketData::IntendedRecipientFingerprint(f) => {
                            Some(f.as_bytes().to_vec())
                        }
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default(),
        ..Default::default()
    };
    let Some((c, i)) = find_signer(certs, sig) else {
        v.status = SigStatus::UnknownKey as i32;
        return v;
    };
    let k = &c.keys[i];
    v.signer_cert = c.keys[0].fpr.as_bytes().to_vec();
    v.signer_key = k.fpr.as_bytes().to_vec();
    v.uids = c.uids.clone();
    if weak(sig.hash_alg()) {
        v.status = SigStatus::WeakHash as i32;
        return v;
    }
    let mut why = 0;
    if c.revoked || k.revoked {
        why |= WHY_REVOKED;
    }
    if !k.valid || !c.keys[0].valid {
        why |= WHY_NO_VALID_BINDING;
    }
    if !k.can_sign {
        why |= WHY_NOT_SIGNING_CAPABLE;
    }
    if k.expires.is_some_and(|x| created >= x) || c.keys[0].expires.is_some_and(|x| created >= x) {
        why |= WHY_EXPIRED_AT_SIGNING;
    }
    if created < k.created {
        why |= WHY_PREDATES_KEY;
    }
    v.status = if !check(c, i) {
        SigStatus::Bad
    } else if why != 0 {
        v.why = why;
        SigStatus::KeyInvalid
    } else {
        SigStatus::Good
    } as i32;
    v
}
