//! The half that holds secret keys. It never parses the encrypted payload.

use std::io::BufReader;

use pgp::composed::{Deserializable, PlainSessionKey, SignedSecretKey};
use pgp::ser::Serialize;
use pgp::types::{DecryptionKey, EskType, Password, PkeskVersion};

use crate::packets::{container, dearmor, refuse_sed, scan};
use crate::{ImportedKey, Reason, Refusal, SecretKey, SessionKey, cert, e};

fn password(passphrase: Option<&[u8]>) -> Password {
    passphrase
        .map(Password::from)
        .unwrap_or_else(Password::empty)
}

fn parse_secret_key(k: &[u8]) -> Result<SignedSecretKey, Refusal> {
    let bin = crate::mpi::canonical_secret_mpis(dearmor(k)?);
    SignedSecretKey::from_reader_single(BufReader::new(&bin[..]))
        .map(|(k, _)| k)
        .map_err(e(Reason::BadKey))
}

/// A key that does not parse is skipped (callers normally pass only the key a PKESK names); if none parses, the first
/// error is returned.
fn secret_keys(keys: &[SecretKey<'_>]) -> Result<Vec<(SignedSecretKey, Password)>, Refusal> {
    let mut out = vec![];
    let mut first_err = None;
    for sk in keys {
        match parse_secret_key(sk.key) {
            Ok(key) => out.push((key, password(sk.passphrase))),
            Err(err) => {
                first_err.get_or_insert(err);
            }
        }
    }
    match (out.is_empty(), first_err) {
        (true, Some(err)) => Err(err),
        (true, None) => Err(Refusal::new(Reason::NoKey, "no secret key")),
        _ => Ok(out),
    }
}

/// PKESK processing only: the session key of `message` (armored or binary) for one of `keys`. The secret key sees the
/// PKESK packets, never the encrypted payload. SED is refused before any key is parsed.
pub fn unwrap(message: &[u8], keys: &[SecretKey<'_>]) -> Result<SessionKey, Refusal> {
    let bin = dearmor(message)?;
    refuse_sed(container(&scan(&bin)))?;
    let keys = secret_keys(keys)?;
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
                                return Ok(SessionKey::V3 {
                                    sym_alg: u8::from(*sym_alg),
                                    key: key.as_ref().to_vec(),
                                });
                            }
                            Ok(Ok(PlainSessionKey::V6 { ref key })) => {
                                return Ok(SessionKey::V6 {
                                    key: key.as_ref().to_vec(),
                                });
                            }
                            Ok(Ok(_)) => {
                                return Err(Refusal::new(Reason::Unsupported, "v5 session key"));
                            }
                            Ok(Err(err)) => {
                                bad_pass.get_or_insert(Refusal::new(
                                    Reason::DecryptFailed,
                                    err.to_string(),
                                ));
                            }
                            Err(err) => {
                                bad_pass.get_or_insert(Refusal::new(
                                    Reason::BadPassphrase,
                                    err.to_string(),
                                ));
                            }
                        }
                    }
                }
            }
            pgp::packet::Packet::SymKeyEncryptedSessionKey(_) => {}
            _ => break, // first non-ESK packet: the encrypted payload is not parsed here
        }
    }
    Err(bad_pass.unwrap_or(Refusal::new(
        Reason::NoKey,
        "no PKESK for the supplied keys",
    )))
}

/// Key import: the passphrase (if any) is removed from every secret component, the bindings are verified, and the key
/// is re-serialised in binary with canonical secret MPIs, together with its public half.
pub fn import_key(key: SecretKey<'_>) -> Result<ImportedKey, Refusal> {
    let mut sk = parse_secret_key(key.key)?;
    let pw = password(key.passphrase);
    sk.primary_key
        .remove_password(&pw)
        .map_err(e(Reason::BadPassphrase))?;
    for s in &mut sk.secret_subkeys {
        s.key
            .remove_password(&pw)
            .map_err(e(Reason::BadPassphrase))?;
    }
    sk.verify_bindings().map_err(e(Reason::BadKey))?;
    let unprotected_key = sk.to_bytes().map_err(e(Reason::BadKey))?;
    let public_key = sk.to_public_key();
    let public_cert = public_key.to_bytes().map_err(e(Reason::BadKey))?;
    let info = cert::info(&cert::from_public(public_key));
    Ok(ImportedKey {
        unprotected_key,
        public_cert,
        info,
    })
}
