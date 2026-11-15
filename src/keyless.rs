//! The half that parses the attacker-controlled payload. No function here takes a secret key.
//!
//! `certs` are transferable public keys (armored or binary); one that does not parse is ignored.

use std::io::{BufReader, Read};

use pgp::composed::{
    CleartextSignedMessage, DecryptionOptions, Deserializable, DetachedSignature, Message,
    PlainSessionKey, TheRing,
};
use pgp::crypto::sym::SymmetricKeyAlgorithm;

use crate::cert::{self, Cert};
use crate::packets::{container, dearmor, is_armored, refuse_sed, scan};
use crate::{
    CertInfo, Decrypted, MAX_PLAINTEXT, Reason, Refusal, SessionKey, SignatureVerdict, Verified, e,
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
