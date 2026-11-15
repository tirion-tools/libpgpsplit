//! The operations, on protobuf requests.

use std::io::{BufReader, Read};

use proto::v1::crypto::{
    CertInfo, Container, CryptoRequest, CryptoResponse, Reason, SessionKey,
};
use pgp::composed::{
    CleartextSignedMessage, DecryptionOptions, Deserializable, DetachedSignature, Message,
    PlainSessionKey, SignedSecretKey, TheRing,
};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::ser::Serialize;
use pgp::types::{DecryptionKey, EskType, Password, PkeskVersion};

use crate::cert::{self, Cert};
use crate::{MAX_PLAINTEXT, R, Refusal, e};

/// Run `$body` with `$k` bound to the concrete key type of component `$i` of `$c` (0 = primary).
macro_rules! with_key {
    ($c:expr, $i:expr, |$k:ident| $body:expr) => {
        if $i == 0 {
            let $k = &$c.cert.primary_key;
            $body
        } else {
            let $k = &$c.cert.public_subkeys[$i - 1].key;
            $body
        }
    };
}

pub(crate) fn is_armored(d: &[u8]) -> bool {
    let t = d
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .map(|i| &d[i..])
        .unwrap_or(d);
    t.starts_with(b"-----BEGIN PGP")
}

fn dearmor(d: &[u8]) -> Result<Vec<u8>, Refusal> {
    if !is_armored(d) {
        return Ok(d.to_vec());
    }
    let mut out = Vec::new();
    pgp::armor::Dearmor::new(BufReader::new(d))
        .take(MAX_PLAINTEXT + 1)
        .read_to_end(&mut out)
        .map_err(e(Reason::Malformed))?;
    Ok(out)
}

/// Top-level packet tags (and the SEIPD version) of a binary message, without decrypting anything. This is the
/// structural scan the SED refusal relies on; it is fuzzed (fuzz/fuzz_targets/crypto_packets.rs).
pub fn scan(bin: &[u8]) -> Vec<(u8, Option<u8>)> {
    let mut out = vec![];
    let mut i = 0usize;
    while i < bin.len() && out.len() < 64 {
        let h = bin[i];
        if h & 0x80 == 0 {
            break;
        }
        let (tag, hl, len, partial) = if h & 0x40 != 0 {
            let tag = h & 0x3f;
            let Some(&l0) = bin.get(i + 1) else { break };
            match l0 {
                0..=191 => (tag, 2, l0 as usize, false),
                192..=223 => match bin.get(i + 2) {
                    Some(&l1) => (
                        tag,
                        3,
                        (((l0 as usize) - 192) << 8) + l1 as usize + 192,
                        false,
                    ),
                    None => break,
                },
                255 => match bin.get(i + 2..i + 6) {
                    Some(b) => (
                        tag,
                        6,
                        u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize,
                        false,
                    ),
                    None => break,
                },
                _ => (tag, 2, 0, true),
            }
        } else {
            let tag = (h >> 2) & 0x0f;
            match h & 3 {
                0 => (tag, 2, *bin.get(i + 1).unwrap_or(&0) as usize, false),
                1 => (
                    tag,
                    3,
                    bin.get(i + 1..i + 3)
                        .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
                        .unwrap_or(0),
                    false,
                ),
                2 => (
                    tag,
                    5,
                    bin.get(i + 1..i + 5)
                        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
                        .unwrap_or(0),
                    false,
                ),
                _ => (tag, 1, 0, true),
            }
        };
        let ver = if tag == 18 {
            bin.get(i + hl).copied()
        } else {
            None
        };
        out.push((tag, ver));
        if partial {
            break; // a partial-length body runs to the end of what we care about
        }
        i = i.saturating_add(hl).saturating_add(len);
    }
    out
}

pub fn container(tags: &[(u8, Option<u8>)]) -> Container {
    for (t, v) in tags {
        match (t, v) {
            (18, Some(1)) => return Container::SeipdV1,
            (18, Some(2)) => return Container::SeipdV2,
            (18, _) => return Container::Unknown,
            (20, _) => return Container::Ocbed,
            (9, _) => return Container::Sed,
            _ => {}
        }
    }
    Container::None
}

fn parse_message(d: &[u8]) -> Result<Message<'_>, Refusal> {
    if is_armored(d) {
        Message::from_armor(BufReader::new(d))
            .map(|(m, _)| m)
            .map_err(e(Reason::Malformed))
    } else {
        Message::from_bytes(BufReader::new(d)).map_err(e(Reason::Malformed))
    }
}

fn pw_of(pw: &Option<Vec<u8>>) -> Password {
    pw.as_deref()
        .map(Password::from)
        .unwrap_or_else(Password::empty)
}

fn parse_secret_key(k: &[u8]) -> Result<SignedSecretKey, Refusal> {
    let bin = crate::mpi::canonical_secret_mpis(dearmor(k)?);
    SignedSecretKey::from_reader_single(BufReader::new(&bin[..]))
        .map(|(k, _)| k)
        .map_err(e(Reason::BadKey))
}

/// Secret keys of the request. A key that does not parse is skipped (the caller normally sends only the key a PKESK
/// names); if none parses, the first error is returned.
fn secret_keys(req: &CryptoRequest) -> Result<Vec<(SignedSecretKey, Password)>, Refusal> {
    let mut out = vec![];
    let mut first_err = None;
    for sk in &req.secret_keys {
        match parse_secret_key(&sk.key) {
            Ok(key) => out.push((key, pw_of(&sk.passphrase))),
            Err(err) => {
                first_err.get_or_insert(err);
            }
        }
    }
    match (out.is_empty(), first_err) {
        (true, Some(err)) => Err(err),
        (true, None) => Err((Reason::NoKey, "no secret key".into())),
        _ => Ok(out),
    }
}

fn integrity_error(s: &str) -> bool {
    let l = s.to_lowercase();
    [
        "mdc",
        "modification detection",
        "integrity",
        "tag mismatch",
        "authentication",
        "aead",
        "ocb",
    ]
    .iter()
    .any(|k| l.contains(k))
}

fn message_sigs(
    msg: &Message<'_>,
    certs: &[Cert],
) -> Vec<proto::v1::crypto::SignatureVerdict> {
    let Message::Signed { reader, .. } = msg else {
        return vec![];
    };
    let mut out = vec![];
    for i in 0..reader.num_signatures() {
        let Some(sig) = reader.signature(i) else {
            continue;
        };
        out.push(cert::judge(certs, sig, &|c, k| {
            with_key!(c, k, |key| msg.verify_nested_explicit(i, key).is_ok())
        }));
    }
    out
}

fn session_key_from(s: &Option<SessionKey>) -> Result<PlainSessionKey, Refusal> {
    match s {
        Some(SessionKey {
            version: 3,
            sym_alg,
            key,
        }) if !key.is_empty() && *sym_alg <= 255 => Ok(PlainSessionKey::V3_4 {
            sym_alg: SymmetricKeyAlgorithm::from(*sym_alg as u8),
            key: key.clone().into(),
        }),
        Some(SessionKey {
            version: 6, key, ..
        }) if !key.is_empty() => Ok(PlainSessionKey::V6 {
            key: key.clone().into(),
        }),
        _ => Err((Reason::Protocol, "bad session key".into())),
    }
}

/// Reads the (decrypted, decompressed) literal data through the plaintext cap; nothing read leaves on error.
fn read_plain(msg: &mut Message<'_>) -> Result<Vec<u8>, Refusal> {
    let mut plain = Vec::new();
    if let Err(err) = msg.take(MAX_PLAINTEXT + 1).read_to_end(&mut plain) {
        let s = err.to_string();
        let reason = if integrity_error(&s) {
            Reason::IntegrityFailure
        } else {
            Reason::DecryptFailed
        };
        return Err((reason, s));
    }
    if plain.len() as u64 > MAX_PLAINTEXT {
        return Err((Reason::TooLarge, "plaintext over limit".into()));
    }
    Ok(plain)
}

/// Keyless: the session key from OP_UNWRAP decrypts the payload; signatures inside (combined form) are judged.
pub fn decrypt_session(req: &CryptoRequest) -> R {
    let bin = dearmor(&req.data)?;
    let tags = scan(&bin);
    let cont = container(&tags);
    let pkesk = tags.iter().filter(|t| t.0 == 1).count() as u32;
    // Policy before any key is touched: malleable SED is never decrypted (EFAIL).
    if cont == Container::Sed {
        return Err((
            Reason::NoIntegrity,
            "Symmetrically Encrypted Data packet (no MDC)".into(),
        ));
    }
    let msg = Message::from_bytes(BufReader::new(&bin[..])).map_err(e(Reason::Malformed))?;
    if !msg.is_encrypted() {
        return Err((Reason::NotEncrypted, "no encryption container".into()));
    }
    let ring = TheRing {
        session_keys: vec![session_key_from(&req.session_key)?],
        decrypt_options: DecryptionOptions::new().enable_gnupg_aead(),
        ..Default::default()
    };
    let (mut msg, _) = msg.decrypt_the_ring(ring, true).map_err(|err| {
        let s = err.to_string();
        let reason = if integrity_error(&s) {
            Reason::IntegrityFailure
        } else {
            Reason::DecryptFailed
        };
        (reason, s)
    })?;
    let mut depth = 0;
    while msg.is_compressed() && depth < 2 {
        msg = msg.decompress().map_err(e(Reason::Malformed))?;
        depth += 1;
    }
    let payload = read_plain(&mut msg)?;
    let certs = cert::load_certs(&req.certs);
    Ok(CryptoResponse {
        container: cont as i32,
        pkesk_count: pkesk,
        signatures: message_sigs(&msg, &certs),
        payload,
        ..Default::default()
    })
}

/// Keyed: PKESK processing only. The private key sees the PKESK packets, never the encrypted payload.
pub fn unwrap(req: &CryptoRequest) -> R {
    let bin = dearmor(&req.data)?;
    // Refuse SED before the key is used, as the keyless side does.
    if container(&scan(&bin)) == Container::Sed {
        return Err((
            Reason::NoIntegrity,
            "Symmetrically Encrypted Data packet (no MDC)".into(),
        ));
    }
    let keys = secret_keys(req)?;
    let parser = pgp::packet::PacketParser::new(BufReader::new(&bin[..]));
    let mut bad_pass = None;
    for pkt in parser {
        let pkt = pkt.map_err(e(Reason::Malformed))?;
        match pkt {
            pgp::packet::Packet::PublicKeyEncryptedSessionKey(esk) => {
                let typ = match esk.version() {
                    PkeskVersion::V3 => EskType::V3_4,
                    PkeskVersion::V6 => EskType::V6,
                    _ => continue,
                };
                let Ok(values) = esk.values() else { continue };
                for (k, pw) in &keys {
                    let mut cands: Vec<&dyn DecryptionKey> = vec![];
                    if esk.match_identity(&k.primary_key) {
                        cands.push(&k.primary_key);
                    }
                    for s in &k.secret_subkeys {
                        if esk.match_identity(&s.key) {
                            cands.push(&s.key);
                        }
                    }
                    for d in cands {
                        match d.decrypt(pw, values, typ) {
                            Ok(Ok(PlainSessionKey::V3_4 {
                                ref sym_alg,
                                ref key,
                            })) => {
                                let session_key = SessionKey {
                                    version: 3,
                                    sym_alg: u8::from(*sym_alg) as u32,
                                    key: key.as_ref().to_vec(),
                                };
                                return Ok(CryptoResponse {
                                    session_key: Some(session_key),
                                    ..Default::default()
                                });
                            }
                            Ok(Ok(PlainSessionKey::V6 { ref key })) => {
                                let session_key = SessionKey {
                                    version: 6,
                                    sym_alg: 0,
                                    key: key.as_ref().to_vec(),
                                };
                                return Ok(CryptoResponse {
                                    session_key: Some(session_key),
                                    ..Default::default()
                                });
                            }
                            Ok(Ok(_)) => {
                                return Err((Reason::Unsupported, "v5 session key".into()));
                            }
                            Ok(Err(err)) => {
                                bad_pass.get_or_insert((Reason::DecryptFailed, err.to_string()));
                            }
                            Err(err) => {
                                bad_pass.get_or_insert((Reason::BadPassphrase, err.to_string()));
                            }
                        }
                    }
                }
            }
            pgp::packet::Packet::SymKeyEncryptedSessionKey(_) => {}
            _ => break, // first non-ESK packet: the encrypted payload is not parsed here
        }
    }
    Err(bad_pass.unwrap_or((Reason::NoKey, "no PKESK for the supplied keys".into())))
}

/// Keyed: key import. The passphrase (if any) is removed from every secret component and the key re-serialised
/// in binary with canonical secret MPIs; the caller stores the result in the Secret Service and the public half
/// (certs[0]) in the profile.
pub fn import_key(req: &CryptoRequest) -> R {
    let [sk] = req.secret_keys.as_slice() else {
        return Err((Reason::Protocol, "exactly one secret key".into()));
    };
    let mut key = parse_secret_key(&sk.key)?;
    let pw = pw_of(&sk.passphrase);
    key.primary_key
        .remove_password(&pw)
        .map_err(e(Reason::BadPassphrase))?;
    for s in &mut key.secret_subkeys {
        s.key
            .remove_password(&pw)
            .map_err(e(Reason::BadPassphrase))?;
    }
    key.verify_bindings().map_err(e(Reason::BadKey))?;
    let unprotected_key = key.to_bytes().map_err(e(Reason::BadKey))?;
    let public_key = key.to_public_key();
    let public_cert = public_key.to_bytes().map_err(e(Reason::BadKey))?;
    let public = cert::from_public(public_key);
    Ok(CryptoResponse {
        certs: vec![cert::info(&public)],
        unprotected_key,
        public_cert,
        ..Default::default()
    })
}

pub fn verify_detached(req: &CryptoRequest) -> R {
    let sig = if is_armored(&req.signature) {
        DetachedSignature::from_armor_single(BufReader::new(&req.signature[..])).map(|(s, _)| s)
    } else {
        DetachedSignature::from_reader_single(BufReader::new(&req.signature[..])).map(|(s, _)| s)
    }
    .map_err(e(Reason::Malformed))?;
    let certs = cert::load_certs(&req.certs);
    let data = &req.data;
    let v = cert::judge(&certs, &sig.signature, &|c, k| {
        with_key!(c, k, |key| sig.signature.verify(key, &data[..]).is_ok())
    });
    Ok(CryptoResponse {
        signatures: vec![v],
        ..Default::default()
    })
}

pub fn verify_cleartext(req: &CryptoRequest) -> R {
    let text = std::str::from_utf8(&req.data).map_err(e(Reason::Malformed))?;
    let (msg, _headers) =
        CleartextSignedMessage::from_string(text).map_err(e(Reason::Malformed))?;
    let certs = cert::load_certs(&req.certs);
    let normalized = msg.signed_text();
    let signatures = msg
        .signatures()
        .iter()
        .map(|sig| {
            cert::judge(&certs, sig, &|c, k| {
                with_key!(c, k, |key| sig.verify(key, normalized.as_bytes()).is_ok())
            })
        })
        .collect();
    // Only the signed text is returned for display; armor headers (e.g. "Hash:") are dropped.
    Ok(CryptoResponse {
        signatures,
        payload: msg.text().as_bytes().to_vec(),
        ..Default::default()
    })
}

pub fn verify_message(req: &CryptoRequest) -> R {
    let mut msg = parse_message(&req.data)?;
    if msg.is_encrypted() {
        return Err((
            Reason::Protocol,
            "encrypted message: use unwrap + decrypt".into(),
        ));
    }
    if msg.is_compressed() {
        msg = msg.decompress().map_err(e(Reason::Malformed))?;
    }
    let payload = read_plain(&mut msg).map_err(|(r, d)| {
        (
            if r == Reason::TooLarge {
                r
            } else {
                Reason::Malformed
            },
            d,
        )
    })?;
    let certs = cert::load_certs(&req.certs);
    Ok(CryptoResponse {
        signatures: message_sigs(&msg, &certs),
        payload,
        ..Default::default()
    })
}

pub fn cert_info(req: &CryptoRequest) -> R {
    let certs = req
        .certs
        .iter()
        .map(|c| {
            cert::load_cert(c)
                .map(|c| cert::info(&c))
                .unwrap_or(CertInfo {
                    valid: false,
                    ..Default::default()
                })
        })
        .collect();
    Ok(CryptoResponse {
        certs,
        ..Default::default()
    })
}
