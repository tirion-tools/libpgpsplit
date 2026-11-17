//! The half that holds secret keys. It never parses the encrypted payload. Signing and key generation live here too:
//! they hold (or create) secret key material.

use std::io::BufReader;

use pgp::composed::{
    Deserializable, DetachedSignature, KeyType, MessageBuilder, PlainSessionKey, SignedKeyDetails,
    SignedSecretKey, SignedSecretSubKey, SubpacketConfig,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{
    Features, KeyFlags, PacketTrait, PubKeyInner, PublicKey, PublicSubkey, RevocationCode,
    SecretSubkey, SignatureConfig, SignatureType, SignatureVersionSpecific, Subpacket,
    SubpacketData, UserId,
};
use pgp::ser::Serialize;
use pgp::types::{
    CompressionAlgorithm, DecryptionKey, EskType, Fingerprint, KeyDetails, KeyVersion, Password,
    PkeskVersion, SigningKey, Tag, Timestamp, VerifyingKey,
};
use rand_core::OsRng;

use crate::packets::{container, dearmor, refuse_sed, scan};
use crate::{
    GeneratedKey, KeyPair, MAX_PLAINTEXT, Reason, Refusal, RenewedKey, SecretKey, SessionKey,
    SignMode, Signed, cert, e,
};

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
pub fn import_key(key: SecretKey<'_>) -> Result<KeyPair, Refusal> {
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
    key_pair(&sk)
}

/// The binary secret key, its public half and its certificate information, after checking every binding.
fn key_pair(sk: &SignedSecretKey) -> Result<KeyPair, Refusal> {
    sk.verify_bindings().map_err(e(Reason::BadKey))?;
    let unprotected_key = sk.to_bytes().map_err(e(Reason::BadKey))?;
    let public_key = sk.to_public_key();
    let public_cert = public_key.to_bytes().map_err(e(Reason::BadKey))?;
    let info = cert::info(&cert::from_public(public_key));
    Ok(KeyPair {
        unprotected_key,
        public_cert,
        info,
    })
}

/// The signing component of `sk` valid at `created`, its public half, and whether its secret is passphrase-protected:
/// the newest valid signing subkey (bound with a back-signature), else the primary key. Validity, revocation and expiry
/// are judged by the same certificate semantics as verification.
fn signing_component(
    sk: &SignedSecretKey,
    created: u32,
) -> Result<(&dyn SigningKey, &dyn VerifyingKey, bool), Refusal> {
    let c = cert::from_public(sk.to_public_key());
    let primary = &c.keys[0];
    let usable = |k: &cert::KeyEntry| {
        k.valid
            && k.can_sign
            && !k.revoked
            && k.created <= created
            && k.expires.is_none_or(|x| created < x)
    };
    let primary_ok = primary.valid && !c.revoked && primary.expires.is_none_or(|x| created < x);
    let best = c.keys[1..]
        .iter()
        .filter(|k| usable(k))
        .max_by_key(|k| k.created)
        .or_else(|| usable(primary).then_some(primary))
        .filter(|_| primary_ok)
        .ok_or_else(|| Refusal::new(Reason::BadKey, "no valid signing key"))?;
    if best.fpr == sk.primary_key.fingerprint() {
        let k = &sk.primary_key;
        return Ok((k, k.public_key(), k.secret_params().is_encrypted()));
    }
    sk.secret_subkeys
        .iter()
        .find(|s| s.key.fingerprint() == best.fpr)
        .map(|s| {
            (
                &s.key as &dyn SigningKey,
                s.key.public_key() as &dyn VerifyingKey,
                s.key.secret_params().is_encrypted(),
            )
        })
        .ok_or_else(|| Refusal::new(Reason::BadKey, "signing key has no secret part"))
}

/// Refuses a secret that does not belong to its public key: a test signature must verify with the public half. The
/// two-octet checksum is the only integrity check of an unprotected secret, and rPGP signs with the secret alone, so a
/// corrupted or substituted secret would otherwise produce signatures that no one can verify.
fn check_pair(
    signer: &dyn SigningKey,
    public: &dyn VerifyingKey,
    pw: &Password,
    hash: HashAlgorithm,
    locked: impl Fn(pgp::errors::Error) -> Refusal,
) -> Result<(), Refusal> {
    let digest = hash
        .digest(b"libpgpsplit key pair check")
        .map_err(e(Reason::BadKey))?;
    let sig = signer.sign(pw, hash, &digest).map_err(locked)?;
    public.verify(hash, &digest, &sig).map_err(|_| {
        Refusal::new(
            Reason::BadKey,
            "the secret key does not match its public key",
        )
    })
}

/// SHA-256, or the key's own stronger default (P-384/P-521 and v6 Ed448 ask for more). Never SHA-1.
fn data_hash(key: &dyn SigningKey) -> HashAlgorithm {
    match key.hash_alg() {
        h @ (HashAlgorithm::Sha384
        | HashAlgorithm::Sha512
        | HashAlgorithm::Sha3_256
        | HashAlgorithm::Sha3_512) => h,
        _ => HashAlgorithm::Sha256,
    }
}

fn sub(data: SubpacketData) -> Result<Subpacket, Refusal> {
    Subpacket::regular(data).map_err(e(Reason::InvalidRequest))
}

/// An RFC 9580 fingerprint from its bytes: 20 (v4) or 32 (v6).
fn fingerprint(fp: &[u8]) -> Result<Fingerprint, Refusal> {
    let v = match fp.len() {
        20 => KeyVersion::V4,
        32 => KeyVersion::V6,
        n => {
            return Err(Refusal::new(
                Reason::InvalidRequest,
                format!("intended recipient fingerprint of {n} bytes"),
            ));
        }
    };
    Fingerprint::new(v, fp).map_err(e(Reason::InvalidRequest))
}

/// Signs `data` with the signing key of `key` (see [`SignMode`]). The signature creation time is `created` (Unix
/// seconds), not the clock, so a v4 signature is a function of its inputs: Ed25519, ECDSA (RFC 6979) and RSA
/// PKCS#1 v1.5 signatures are deterministic. v6 signatures carry a random salt (RFC 9580 §5.2.3), so they differ
/// on every call. The hash is SHA-256 or stronger. `intended_recipients` are primary-key fingerprints (20 or 32
/// bytes), each written as a hashed Intended Recipient Fingerprint subpacket (RFC 9580 §5.2.3.36).
pub fn sign(
    key: SecretKey<'_>,
    data: &[u8],
    mode: SignMode,
    intended_recipients: &[&[u8]],
    created: u32,
) -> Result<Signed, Refusal> {
    let sk = parse_secret_key(key.key)?;
    let (signer, public, protected) = signing_component(&sk, created)?;
    let pw = password(key.passphrase);
    let mut hashed = vec![
        sub(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
            created,
        )))?,
        sub(SubpacketData::IssuerFingerprint(signer.fingerprint()))?,
    ];
    for r in intended_recipients {
        hashed.push(sub(SubpacketData::IntendedRecipientFingerprint(
            fingerprint(r)?,
        ))?);
    }
    let mut unhashed = vec![];
    if signer.version() <= KeyVersion::V4 {
        unhashed.push(sub(SubpacketData::IssuerKeyId(signer.legacy_key_id()))?);
    }
    let subpackets = SubpacketConfig::UserDefined { hashed, unhashed };
    let hash = data_hash(signer);
    // A signing failure is a wrong passphrase when the key is protected, else a key rPGP cannot sign with.
    let locked = |err: pgp::errors::Error| {
        let reason = if protected {
            Reason::BadPassphrase
        } else {
            Reason::BadKey
        };
        Refusal::new(reason, err.to_string())
    };
    check_pair(signer, public, &pw, hash, locked)?;
    let out = match mode {
        SignMode::Detached => DetachedSignature::sign_binary_data_with_subpackets(
            OsRng,
            &Box::new(signer),
            &pw,
            hash,
            data,
            subpackets,
        )
        .map_err(locked)?
        .to_armored_bytes(Default::default())
        .map_err(e(Reason::InvalidRequest))?,
        SignMode::Inline => {
            let mut b = MessageBuilder::from_bytes("", data.to_vec());
            b.sign_with_subpackets(signer, pw, hash, subpackets);
            b.to_vec(OsRng).map_err(locked)?
        }
    };
    if out.len() as u64 > MAX_PLAINTEXT {
        return Err(Refusal::new(Reason::TooLarge, "signed output over limit"));
    }
    Ok(Signed {
        payload: out,
        hash_alg: u8::from(hash),
    })
}

/// The key expiration time subpacket for a key created at `key_created` that should expire at `until`.
fn expiry(key_created: u32, until: u32) -> Result<Subpacket, Refusal> {
    let secs = until
        .checked_sub(key_created)
        .filter(|s| *s > 0)
        .ok_or_else(|| Refusal::new(Reason::InvalidRequest, "expiry before key creation"))?;
    let d = pgp::types::Duration::try_from(std::time::Duration::from_secs(u64::from(secs)))
        .map_err(e(Reason::InvalidRequest))?;
    sub(SubpacketData::KeyExpirationTime(d))
}

/// `created + lifetime`, refused when it does not fit an OpenPGP timestamp; `None` for no expiry.
fn until(created: u32, lifetime: Option<u32>) -> Result<Option<u32>, Refusal> {
    lifetime
        .map(|l| {
            created
                .checked_add(l)
                .filter(|_| l > 0)
                .ok_or_else(|| Refusal::new(Reason::InvalidRequest, "lifetime out of range"))
        })
        .transpose()
}

/// Generates a new key: a v4 Ed25519 primary key (certify, sign) with a Curve25519 ECDH encryption subkey, the profile
/// that RFC 4880 implementations (GnuPG 2.4 among them) and RFC 9580 ones all read. `user_ids` are self-certified, the
/// first as primary. Every packet and self-signature is dated `created` (Unix seconds); the primary key and the subkey
/// expire `lifetime` seconds later (`None`: never). The secret key is returned unprotected (like [`import_key`]); the
/// caller stores it, and stores the revocation certificate apart from it.
pub fn generate_key(
    user_ids: &[&str],
    created: u32,
    lifetime: Option<u32>,
) -> Result<GeneratedKey, Refusal> {
    if user_ids.is_empty() || user_ids.iter().any(|u| u.is_empty()) {
        return Err(Refusal::new(
            Reason::InvalidRequest,
            "at least one non-empty User ID",
        ));
    }
    let until = until(created, lifetime)?;
    let at = Timestamp::from_secs(created);
    let pw = Password::empty();

    let (params, secret) = KeyType::Ed25519Legacy
        .generate(OsRng)
        .map_err(e(Reason::BadKey))?;
    let inner = PubKeyInner::new(
        KeyVersion::V4,
        KeyType::Ed25519Legacy.to_alg(),
        at,
        None,
        params,
    )
    .map_err(e(Reason::BadKey))?;
    let public = PublicKey::from_inner(inner).map_err(e(Reason::BadKey))?;
    let primary = pgp::packet::SecretKey::new(public.clone(), secret).map_err(e(Reason::BadKey))?;

    let enc_type = KeyType::ECDH(ECCCurve::Curve25519Legacy);
    let (params, secret) = enc_type.generate(OsRng).map_err(e(Reason::BadKey))?;
    let inner = PubKeyInner::new(KeyVersion::V4, enc_type.to_alg(), at, None, params)
        .map_err(e(Reason::BadKey))?;
    let sub_public = PublicSubkey::from_inner(inner).map_err(e(Reason::BadKey))?;
    let subkey = SecretSubkey::new(sub_public.clone(), secret).map_err(e(Reason::BadKey))?;

    let base = |flags: KeyFlags| -> Result<Vec<Subpacket>, Refusal> {
        let mut v = vec![
            sub(SubpacketData::SignatureCreationTime(at))?,
            sub(SubpacketData::IssuerFingerprint(primary.fingerprint()))?,
            sub(SubpacketData::KeyFlags(flags))?,
        ];
        if let Some(u) = until {
            v.push(expiry(created, u)?);
        }
        Ok(v)
    };
    let issuer_id = vec![sub(SubpacketData::IssuerKeyId(primary.legacy_key_id()))?];

    let mut primary_flags = KeyFlags::default();
    primary_flags.set_certify(true);
    primary_flags.set_sign(true);
    let mut features = Features::default();
    features.set_seipd_v1(true);
    let mut users = vec![];
    for (i, uid) in user_ids.iter().enumerate() {
        let id = UserId::from_str(Default::default(), uid).map_err(e(Reason::InvalidRequest))?;
        let mut config = SignatureConfig::v4(
            SignatureType::CertPositive,
            primary.algorithm(),
            HashAlgorithm::Sha256,
        );
        config.hashed_subpackets = base(primary_flags.clone())?;
        config.hashed_subpackets.extend([
            sub(SubpacketData::Features(features.clone()))?,
            sub(SubpacketData::PreferredSymmetricAlgorithms(
                (&[SymmetricKeyAlgorithm::AES256, SymmetricKeyAlgorithm::AES128][..]).into(),
            ))?,
            sub(SubpacketData::PreferredHashAlgorithms(
                (&[HashAlgorithm::Sha512, HashAlgorithm::Sha256][..]).into(),
            ))?,
            sub(SubpacketData::PreferredCompressionAlgorithms(
                (&[CompressionAlgorithm::Uncompressed][..]).into(),
            ))?,
        ]);
        if i == 0 {
            config
                .hashed_subpackets
                .push(sub(SubpacketData::IsPrimary(true))?);
        }
        config.unhashed_subpackets = issuer_id.clone();
        let sig = config
            .sign_certification(&primary, &public, &pw, Tag::UserId, &id)
            .map_err(e(Reason::BadKey))?;
        users.push(id.into_signed(sig));
    }

    let mut enc_flags = KeyFlags::default();
    enc_flags.set_encrypt_comms(true);
    enc_flags.set_encrypt_storage(true);
    let mut config = SignatureConfig::v4(
        SignatureType::SubkeyBinding,
        primary.algorithm(),
        HashAlgorithm::Sha256,
    );
    config.hashed_subpackets = base(enc_flags)?;
    config.unhashed_subpackets = issuer_id.clone();
    let binding = config
        .sign_subkey_binding(&primary, &public, &pw, &sub_public)
        .map_err(e(Reason::BadKey))?;

    // The revocation certificate: the primary key and a key revocation signature (reason 0, "no reason specified",
    // as GnuPG and sq pre-generate it), armored as a public key block that either imports.
    let mut config = SignatureConfig::v4(
        SignatureType::KeyRevocation,
        primary.algorithm(),
        HashAlgorithm::Sha256,
    );
    config.hashed_subpackets = vec![
        sub(SubpacketData::SignatureCreationTime(at))?,
        sub(SubpacketData::IssuerFingerprint(primary.fingerprint()))?,
        sub(SubpacketData::RevocationReason(
            RevocationCode::NoReason,
            Default::default(),
        ))?,
    ];
    config.unhashed_subpackets = issuer_id;
    let revocation_sig = config
        .sign_key(&primary, &pw, &public)
        .map_err(e(Reason::BadKey))?;
    let mut revocation = Vec::new();
    public
        .to_writer_with_header(&mut revocation)
        .and_then(|_| revocation_sig.to_writer_with_header(&mut revocation))
        .map_err(e(Reason::BadKey))?;
    let revocation = armored_key_block(&revocation)?;

    let sk = SignedSecretKey {
        primary_key: primary,
        details: SignedKeyDetails {
            revocation_signatures: vec![],
            direct_signatures: vec![],
            users,
            user_attributes: vec![],
        },
        public_subkeys: vec![],
        secret_subkeys: vec![SignedSecretSubKey {
            key: subkey,
            signatures: vec![binding],
        }],
    };
    Ok(GeneratedKey {
        key: key_pair(&sk)?,
        revocation,
    })
}

fn armored_key_block(bin: &[u8]) -> Result<Vec<u8>, Refusal> {
    let mut out = Vec::new();
    pgp::armor::write(
        &crate::packets::Encoded(bin),
        pgp::armor::BlockType::PublicKey,
        &mut out,
        None,
        true,
    )
    .map_err(e(Reason::BadKey))?;
    Ok(out)
}

/// The hashed subpackets of `old` for a re-signature at `at`: its creation time, key expiry and embedded back-signature
/// replaced (`expiry` when the key should expire, `backsig` for a signing subkey), everything else kept.
fn resigned(
    old: &pgp::packet::Signature,
    at: Timestamp,
    expiry: Option<Subpacket>,
    backsig: Option<pgp::packet::Signature>,
) -> Result<SignatureConfig, Refusal> {
    let mut config = old
        .config()
        .cloned()
        .ok_or_else(|| Refusal::new(Reason::BadKey, "self-signature without a configuration"))?;
    if !matches!(config.version_specific, SignatureVersionSpecific::V4) {
        return Err(Refusal::new(Reason::Unsupported, "not a v4 self-signature"));
    }
    config.hashed_subpackets.retain(|p| {
        !matches!(
            p.data,
            SubpacketData::SignatureCreationTime(_)
                | SubpacketData::KeyExpirationTime(_)
                | SubpacketData::EmbeddedSignature(_)
        )
    });
    config
        .hashed_subpackets
        .insert(0, sub(SubpacketData::SignatureCreationTime(at))?);
    config.hashed_subpackets.extend(expiry);
    if let Some(b) = backsig {
        config
            .hashed_subpackets
            .push(sub(SubpacketData::EmbeddedSignature(Box::new(b)))?);
    }
    if matches!(
        config.hash_alg,
        HashAlgorithm::Md5 | HashAlgorithm::Sha1 | HashAlgorithm::Ripemd160
    ) {
        config.hash_alg = HashAlgorithm::Sha256;
    }
    Ok(config)
}

/// Renews a v4 key: every User ID with a valid self-signature and every subkey with a valid binding (not revoked) gets
/// a new self-signature dated `now` (Unix seconds) that keeps the old one's subpackets and expires `lifetime` seconds
/// after `now` (`None`: never); signing subkeys get a fresh back-signature. The superseded self-signatures are dropped,
/// third-party certifications and revocations kept. The fingerprint does not change and the secret key packets come
/// back as given: a passphrase-protected key stays protected (the passphrase unlocks the primary key for signing).
pub fn extend_expiry(
    key: SecretKey<'_>,
    now: u32,
    lifetime: Option<u32>,
) -> Result<RenewedKey, Refusal> {
    let mut sk = parse_secret_key(key.key)?;
    if sk.primary_key.version() != KeyVersion::V4 {
        return Err(Refusal::new(
            Reason::Unsupported,
            "only v4 keys are renewed",
        ));
    }
    let c = cert::from_public(sk.to_public_key());
    if c.revoked {
        return Err(Refusal::new(Reason::BadKey, "the key is revoked"));
    }
    let until = until(now, lifetime)?;
    let at = Timestamp::from_secs(now);
    let pw = password(key.passphrase);
    let protected = sk.primary_key.secret_params().is_encrypted();
    let signing_failed = |err: pgp::errors::Error| {
        let reason = if protected {
            Reason::BadPassphrase
        } else {
            Reason::BadKey
        };
        Refusal::new(reason, err.to_string())
    };
    let primary = sk.primary_key.clone();
    let public = primary.public_key().clone();
    let pcreated = public.created_at().as_secs();
    if now < pcreated {
        return Err(Refusal::new(
            Reason::InvalidRequest,
            "now before key creation",
        ));
    }
    let primary_expiry = until.map(|u| expiry(pcreated, u)).transpose()?;

    let mut renewed = 0;
    for u in &mut sk.details.users {
        let newest = u
            .signatures
            .iter()
            .filter(|s| {
                cert::issued_by_primary(s, &public)
                    && s.verify_certification(&public, Tag::UserId, &u.id).is_ok()
            })
            .max_by_key(|s| s.created().map(|t| t.as_secs()));
        let Some(old) = newest else { continue };
        let config = resigned(old, at, primary_expiry.clone(), None)?;
        let sig = config
            .sign_certification(&primary, &public, &pw, Tag::UserId, &u.id)
            .map_err(signing_failed)?;
        u.signatures.retain(|s| {
            !(s.is_certification()
                && cert::issued_by_primary(s, &public)
                && s.verify_certification(&public, Tag::UserId, &u.id).is_ok())
        });
        u.signatures.push(sig);
        renewed += 1;
    }
    if renewed == 0 {
        return Err(Refusal::new(
            Reason::BadKey,
            "no valid User ID self-signature",
        ));
    }

    for s in &mut sk.secret_subkeys {
        let sub_public = s.key.public_key().clone();
        let revoked = s
            .signatures
            .iter()
            .any(|x| x.typ() == Some(SignatureType::SubkeyRevocation));
        let newest = s
            .signatures
            .iter()
            .filter(|x| x.verify_subkey_binding(&public, &sub_public).is_ok())
            .max_by_key(|x| x.created().map(|t| t.as_secs()));
        let (Some(old), false) = (newest, revoked) else {
            continue;
        };
        let backsig = if old.key_flags().sign() {
            Some(
                s.key
                    .sign_primary_key_binding(OsRng, &public, &pw)
                    .map_err(signing_failed)?,
            )
        } else {
            None
        };
        let sub_expiry = until
            .map(|u| expiry(sub_public.created_at().as_secs(), u))
            .transpose()?;
        let config = resigned(old, at, sub_expiry, backsig)?;
        let sig = config
            .sign_subkey_binding(&primary, &public, &pw, &sub_public)
            .map_err(signing_failed)?;
        s.signatures
            .retain(|x| x.typ() != Some(SignatureType::SubkeyBinding));
        s.signatures.push(sig);
    }

    sk.verify_bindings().map_err(e(Reason::BadKey))?;
    let secret_key = sk.to_bytes().map_err(e(Reason::BadKey))?;
    let public_key = sk.to_public_key();
    let public_cert = public_key.to_bytes().map_err(e(Reason::BadKey))?;
    let info = cert::info(&cert::from_public(public_key));
    Ok(RenewedKey {
        secret_key,
        public_cert,
        info,
    })
}
