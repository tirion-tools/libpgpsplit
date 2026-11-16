//! The half that parses the attacker-controlled payload, and encrypts to certificates. No function here takes a
//! secret key.
//!
//! `certs` are transferable public keys (armored or binary); for decryption and verification one that does not parse
//! is ignored, for [`encrypt`] it is refused.

use std::io::{BufReader, Read};

use pgp::armor::BlockType;
use pgp::composed::{
    CleartextSignedMessage, DecryptionOptions, Deserializable, DetachedSignature, Message,
    MessageBuilder, PlainSessionKey, TheRing,
};
use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{PacketTrait, PublicKeyEncryptedSessionKey, SymEncryptedProtectedData};
use pgp::types::{KeyDetails, KeyVersion};
use rand_core::OsRng;

use crate::cert::{self, Cert};
use crate::packets::{Encoded, container, dearmor, is_armored, refuse_sed, scan};
use crate::{
    CertInfo, Container, Decrypted, MAX_PLAINTEXT, Reason, Refusal, SessionKey, SignatureVerdict,
    Verified, e,
};

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

fn parse_message(d: &[u8]) -> Result<Message<'_>, Refusal> {
    if is_armored(d) {
        Message::from_armor(BufReader::new(d))
            .map(|(m, _)| m)
            .map_err(e(Reason::Malformed))
    } else {
        Message::from_bytes(BufReader::new(d)).map_err(e(Reason::Malformed))
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

fn decrypt_error(s: String) -> Refusal {
    let reason = if integrity_error(&s) {
        Reason::IntegrityFailure
    } else {
        Reason::DecryptFailed
    };
    Refusal::new(reason, s)
}

fn message_sigs(msg: &Message<'_>, certs: &[Cert]) -> Vec<SignatureVerdict> {
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

fn plain_session_key(s: &SessionKey) -> Result<PlainSessionKey, Refusal> {
    match s {
        SessionKey::V3 { sym_alg, key } if !key.is_empty() => Ok(PlainSessionKey::V3_4 {
            sym_alg: SymmetricKeyAlgorithm::from(*sym_alg),
            key: key.clone().into(),
        }),
        SessionKey::V6 { key } if !key.is_empty() => Ok(PlainSessionKey::V6 {
            key: key.clone().into(),
        }),
        _ => Err(Refusal::new(Reason::InvalidRequest, "bad session key")),
    }
}

/// Reads the (decrypted, decompressed) literal data through the plaintext cap; nothing read leaves on error.
fn read_plain(msg: &mut Message<'_>) -> Result<Vec<u8>, Refusal> {
    let mut plain = Vec::new();
    if let Err(err) = msg.take(MAX_PLAINTEXT + 1).read_to_end(&mut plain) {
        return Err(decrypt_error(err.to_string()));
    }
    if plain.len() as u64 > MAX_PLAINTEXT {
        return Err(Refusal::new(Reason::TooLarge, "plaintext over limit"));
    }
    Ok(plain)
}

/// Decrypts `message` (armored or binary) with the session key from [`crate::keyed::unwrap`]; signatures inside
/// (combined form) are judged against `certs`. SED is refused before the session key is used.
pub fn decrypt<C: AsRef<[u8]>>(
    message: &[u8],
    session_key: &SessionKey,
    certs: &[C],
) -> Result<Decrypted, Refusal> {
    let bin = dearmor(message)?;
    let tags = scan(&bin);
    let cont = container(&tags);
    let pkesk_count = tags.iter().filter(|t| t.0 == 1).count() as u32;
    refuse_sed(cont)?;
    let msg = Message::from_bytes(BufReader::new(&bin[..])).map_err(e(Reason::Malformed))?;
    if !msg.is_encrypted() {
        return Err(Refusal::new(
            Reason::NotEncrypted,
            "no encryption container",
        ));
    }
    let ring = TheRing {
        session_keys: vec![plain_session_key(session_key)?],
        decrypt_options: DecryptionOptions::new().enable_gnupg_aead(),
        ..Default::default()
    };
    let (mut msg, _) = msg
        .decrypt_the_ring(ring, true)
        .map_err(|err| decrypt_error(err.to_string()))?;
    let mut depth = 0;
    while msg.is_compressed() && depth < 2 {
        msg = msg.decompress().map_err(e(Reason::Malformed))?;
        depth += 1;
    }
    let payload = read_plain(&mut msg)?;
    let certs = cert::load_certs(certs);
    Ok(Decrypted {
        container: cont,
        pkesk_count,
        signatures: message_sigs(&msg, &certs),
        payload,
    })
}

/// One detached signature (armored or binary) over the exact bytes `data`.
pub fn verify_detached<C: AsRef<[u8]>>(
    data: &[u8],
    signature: &[u8],
    certs: &[C],
) -> Result<SignatureVerdict, Refusal> {
    let sig = if is_armored(signature) {
        DetachedSignature::from_armor_single(BufReader::new(signature)).map(|(s, _)| s)
    } else {
        DetachedSignature::from_reader_single(BufReader::new(signature)).map(|(s, _)| s)
    }
    .map_err(e(Reason::Malformed))?;
    let certs = cert::load_certs(certs);
    Ok(cert::judge(&certs, &sig.signature, &|c, k| {
        with_key!(c, k, |key| sig.signature.verify(key, data).is_ok())
    }))
}

/// A cleartext-signed block. The payload is the signed text only; armor headers (e.g. "Hash:") are dropped.
pub fn verify_cleartext<C: AsRef<[u8]>>(text: &[u8], certs: &[C]) -> Result<Verified, Refusal> {
    let text = std::str::from_utf8(text).map_err(e(Reason::Malformed))?;
    let (msg, _headers) =
        CleartextSignedMessage::from_string(text).map_err(e(Reason::Malformed))?;
    let certs = cert::load_certs(certs);
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
    Ok(Verified {
        signatures,
        payload: msg.text().as_bytes().to_vec(),
    })
}

/// An inline-signed (or unsigned, possibly compressed) message, armored or binary. The payload is the literal data.
/// An encrypted message is refused: use [`crate::keyed::unwrap`] and [`decrypt`].
pub fn verify_message<C: AsRef<[u8]>>(message: &[u8], certs: &[C]) -> Result<Verified, Refusal> {
    let mut msg = parse_message(message)?;
    if msg.is_encrypted() {
        return Err(Refusal::new(
            Reason::InvalidRequest,
            "encrypted message: use unwrap + decrypt",
        ));
    }
    if msg.is_compressed() {
        msg = msg.decompress().map_err(e(Reason::Malformed))?;
    }
    let payload = read_plain(&mut msg).map_err(|r| match r.reason {
        Reason::TooLarge => r,
        _ => Refusal::new(Reason::Malformed, r.detail),
    })?;
    let certs = cert::load_certs(certs);
    Ok(Verified {
        signatures: message_sigs(&msg, &certs),
        payload,
    })
}

/// Certificate semantics of one transferable public key (armored or binary); `None` when it does not parse.
pub fn cert_info(cert: &[u8]) -> Option<CertInfo> {
    cert::load_cert(cert).map(|c| cert::info(&c))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// The components of `c` that can take a session key at `now`: valid binding, encryption flags, not revoked, created
/// by `now`, not expired at `now`; none when the certificate itself is revoked, unbound or expired.
fn encryption_keys(c: &Cert, now: u32) -> Vec<usize> {
    let p = &c.keys[0];
    if c.revoked || !p.valid || p.expires.is_some_and(|x| now >= x) {
        return vec![];
    }
    c.keys
        .iter()
        .enumerate()
        .filter(|(_, k)| {
            k.valid
                && k.can_encrypt
                && !k.revoked
                && k.created <= now
                && k.expires.is_none_or(|x| now < x)
        })
        .map(|(i, _)| i)
        .collect()
}

/// Encrypts `data` to every certificate in `certs` (each recipient, the sender's own certificate included) and returns
/// an ASCII-armored OpenPGP message (RFC 3156 §4 body). Each certificate's usable encryption keys at `now` (Unix
/// seconds) each get a PKESK; a certificate that does not parse, or has no usable encryption key, refuses the whole
/// request with [`Reason::BadKey`] (the detail names its fingerprint or position). The container is SEIPD v2 (AES-256,
/// OCB) when every recipient is a v6 key, else SEIPD v1 (AES-256 + MDC), which RFC 4880 implementations read; nothing
/// is compressed. With `data_is_message`, `data` is a [`crate::SignMode::Inline`] result and is encrypted as it is
/// (RFC 3156 §6.2); otherwise it goes into a binary literal data packet with no file name and date 0. The session key
/// and the ciphertext are random: two calls never give the same output.
pub fn encrypt<C: AsRef<[u8]>>(
    data: &[u8],
    certs: &[C],
    data_is_message: bool,
    now: u32,
) -> Result<Vec<u8>, Refusal> {
    if certs.is_empty() {
        return Err(Refusal::new(Reason::InvalidRequest, "no recipients"));
    }
    let mut recipients = Vec::with_capacity(certs.len());
    for (i, c) in certs.iter().enumerate() {
        let c = cert::load_cert(c.as_ref()).ok_or_else(|| {
            Refusal::new(Reason::BadKey, format!("certificate {i} does not parse"))
        })?;
        let keys = encryption_keys(&c, now);
        if keys.is_empty() {
            return Err(Refusal::new(
                Reason::BadKey,
                format!("{}: no valid encryption key", hex(c.keys[0].fpr.as_bytes())),
            ));
        }
        recipients.push((c, keys));
    }
    let plain = if data_is_message {
        // A one-pass signed (or plain literal) message: never an encrypted one, never an arbitrary blob.
        let tags = scan(data);
        if container(&tags) != Container::None || !matches!(tags.first(), Some((4 | 11, _))) {
            return Err(Refusal::new(
                Reason::InvalidRequest,
                "data is not a signed or literal OpenPGP message",
            ));
        }
        data.to_vec()
    } else {
        MessageBuilder::from_bytes("", data.to_vec())
            .to_vec(OsRng)
            .map_err(e(Reason::InvalidRequest))?
    };

    let v2 = recipients
        .iter()
        .all(|(c, _)| c.cert.primary_key.version() == KeyVersion::V6);
    let sym = SymmetricKeyAlgorithm::AES256;
    let session_key = sym.new_session_key(OsRng);
    let mut out = Vec::new();
    for (c, keys) in &recipients {
        for &k in keys {
            let pkesk = with_key!(c, k, |key| if v2 {
                PublicKeyEncryptedSessionKey::from_session_key_v6(OsRng, &session_key, key)
            } else {
                PublicKeyEncryptedSessionKey::from_session_key_v3(OsRng, &session_key, sym, key)
            })
            .map_err(|err| {
                Refusal::new(
                    Reason::BadKey,
                    format!("{}: {err}", hex(c.keys[k].fpr.as_bytes())),
                )
            })?;
            pkesk
                .to_writer_with_header(&mut out)
                .map_err(e(Reason::InvalidRequest))?;
        }
    }
    let seipd = if v2 {
        SymEncryptedProtectedData::encrypt_seipdv2(
            OsRng,
            sym,
            AeadAlgorithm::Ocb,
            ChunkSize::default(),
            session_key.as_ref(),
            &plain,
        )
    } else {
        SymEncryptedProtectedData::encrypt_seipdv1(OsRng, sym, session_key.as_ref(), &plain)
    }
    .map_err(e(Reason::InvalidRequest))?;
    seipd
        .to_writer_with_header(&mut out)
        .map_err(e(Reason::InvalidRequest))?;

    let mut armored = Vec::with_capacity(out.len() * 4 / 3 + 128);
    // RFC 9580 §6.2: no CRC-24 for SEIPD v2; kept for v1, which older readers expect.
    pgp::armor::write(&Encoded(&out), BlockType::Message, &mut armored, None, !v2)
        .map_err(e(Reason::InvalidRequest))?;
    if armored.len() as u64 > MAX_PLAINTEXT {
        return Err(Refusal::new(
            Reason::TooLarge,
            "encrypted output over limit",
        ));
    }
    Ok(armored)
}
