# libpgpsplit

OpenPGP split decryption and verification in Rust, on [rPGP](https://github.com/rpgp/rpgp). Decrypting a message is
split in two:

- the **keyed** half holds the secret key and parses only the PKESK packets in front of the encrypted payload. It
  returns the session key.
- the **keyless** half gets that session key and parses the attacker-controlled payload: decryption, decompression,
  literal data, signatures.

Run each half in its own process. The process holding the key then never parses hostile payload, and the process
parsing hostile payload never holds the key.

The send side follows the same split: signing, key generation and key renewal hold secret keys (`keyed`); encryption
to certificates needs none (`keyless`).

## Builds on

This crate is glue around rPGP (`pgp` 0.21.1, MIT OR Apache-2.0); it does not replace it, and fixes found in it go
upstream. rPGP does the packet parsing, the cryptography, decompression (ZIP, ZLIB, BZip2), the cleartext framework
and signature verification.

What it adds:
- the split API: no function in `keyless` takes a secret key;
- refusal of SED (no integrity protection) before any key or session key is used, from a structural scan of the
  top-level packets;
- mapping of MDC/AEAD failures to an integrity refusal, with no plaintext released, and a plaintext cap
  (`MAX_PLAINTEXT`, 64 MiB) that also bounds decompression bombs;
- certificate semantics rPGP leaves to the caller: self-signature and subkey-binding validity (including the
  back-signature of signing subkeys), key flags, expiry, revocation;
- a verdict per data signature: good, bad, unknown key, weak hash (MD5, SHA-1, RIPEMD-160: never good), or key invalid
  with the reasons;
- a re-encoder for the non-minimal secret MPIs some GnuPG versions write (about 1 in 256 Ed25519 keys), which rPGP
  refuses as exported (`canonical_secret_mpis`); it re-encodes only a packet whose stored checksum matches, so a
  corrupted secret is still refused;
- on the send side: the choice of the signing (sub)key and of every recipient's encryption keys by the same
  certificate semantics as verification, signatures dated by the caller (so v4 signatures are deterministic), one
  generation profile with an explicit lifetime and a revocation certificate, and renewal of a key's expiry by
  re-signing its self-signatures (rPGP's key builder has no expiry and dates everything with the clock).

Related projects, and why this crate does not use them:

- [rpgpie](https://codeberg.org/heiko/rpgpie) (MIT OR Apache-2.0) is a higher-level library on rPGP with certificate
  semantics and message decryption. It overlaps with the certificate checks here. It has no split between PKESK
  unwrapping and payload parsing, no SED refusal before key use, no plaintext cap, and no MPI repair; its README
  states that API stability is not a goal yet. Building on it would add chrono, serde and serde_json for
  about 300 lines of certificate checks. Revisit when it stabilises.
- [rsop](https://codeberg.org/heiko/rsop) is the Stateless OpenPGP CLI on rpgpie. SOP's
  `--session-key-out`/`--with-session-key` give the same split, but between whole processes of a CLI rather than
  as a library API.
- [Sequoia](https://sequoia-pgp.org/) has a complete policy layer, but is LGPL-2.0-or-later.

## Scope

In scope: decrypting PKESK-encrypted messages (v3 and v6 PKESK; SEIPD v1, SEIPD v2, GnuPG's OCB Encrypted Data),
verifying detached, cleartext and inline signatures, certificate information, importing a secret key (passphrase
removed, MPIs canonical), and the send side: detached and inline (one-pass) signatures, encryption to certificates
(SEIPD v1, or v2 when every recipient is a v6 key), generating a v4 Ed25519 + Cv25519 key with its revocation
certificate, and extending a v4 key's expiry.

Not in scope:
- MIME (PGP/MIME, inline PGP detection, protected headers): the input is the OpenPGP data itself;
- key storage, key discovery and trust (web of trust, TOFU, WKD);
- policy: key lifetime, when to renew, which recipients to encrypt to are the caller's parameters;
- compression on the send side, cleartext signatures, v6 key generation and renewal;
- the process boundary: launching, confining and talking to the two halves is the caller's;
- symmetric (SKESK, password-only) decryption.

## API

```rust
use pgpsplit::{SecretKey, keyed, keyless};

// keyed process
let session_key = keyed::unwrap(message, &[SecretKey { key: secret_key, passphrase: None }])?;
// keyless process
let d = keyless::decrypt(message, &session_key, &certs)?;
// d.container, d.pkesk_count, d.payload, d.signatures (one SignatureVerdict per signature inside)

let v = keyless::verify_detached(signed_bytes, signature, &certs)?;   // SignatureVerdict
let v = keyless::verify_cleartext(cleartext_block, &certs)?;          // Verified { signatures, payload }
let v = keyless::verify_message(inline_signed_message, &certs)?;      // Verified
let info = keyless::cert_info(cert);                                  // Option<CertInfo>
let imported = keyed::import_key(SecretKey { key, passphrase: Some(b"...") })?;
// imported.unprotected_key, imported.public_cert, imported.info

// send side
let s = keyed::sign(secret, data, SignMode::Detached, &[], now)?;     // Signed { payload, hash_alg }
let inline = keyed::sign(secret, data, SignMode::Inline, &[recipient_fpr], now)?;
let msg = keyless::encrypt(&inline.payload, &certs, true, now)?;      // armored; false = data in a literal packet
let g = keyed::generate_key(&["Name <addr>"], now, Some(lifetime))?;  // GeneratedKey { key: KeyPair, revocation }
let r = keyed::extend_expiry(secret, now, Some(lifetime))?;           // RenewedKey { secret_key, public_cert, info }
```

- Inputs may be armored or binary. `certs` is any slice of byte buffers; a certificate that does not parse is
  ignored.
- Every operation either returns its result or a `Refusal { reason, detail }`. `detail` is diagnostic only and never
  carries plaintext.
- `Reason` (1–11), `Container` (1–6) and `SigStatus` (1–5) have stable discriminants, so a wire format can carry them as
  integers.
- `SessionKey` is `V3 { sym_alg, key }` or `V6 { key }`.
- `SignatureVerdict` has the status, the `WHY_*` bits for `KeyInvalid`, the issuer, creation time, hash algorithm,
  the signer (`cert`/`key` fingerprints and self-certified User IDs) when the issuer is among the certificates, and
  the Intended Recipient fingerprints.
- **Time.** Key validity is judged at signature creation time: expired at signing, signature older than the key.
  There is no "now" parameter. A caller that wants to know whether a key has expired by now compares
  `KeyInfo::expires` with its own clock.
- The literal-data file name is never returned. There is no session-key cache.
- **Send side.** Creation times are parameters, never the clock. A signature uses the newest valid signing subkey,
  else the primary key, valid at that time; SHA-256 or the key's stronger default. Before signing, a test signature
  must verify with the signing key's public half (`BadKey` otherwise): rPGP signs with the secret alone, and the
  two-octet checksum is the only integrity check of an unprotected secret. `encrypt` refuses the whole request
  (`BadKey`, with the fingerprint or position) when one certificate does not parse or has no valid, unexpired,
  unrevoked encryption key at `now`, and encrypts to every such key of every certificate with AES-256. Generated keys
  are returned unprotected; `extend_expiry` returns the secret key packets as given (protection unchanged), replaces
  the superseded self-signatures and gives signing subkeys a fresh back-signature. The revocation certificate is the
  primary key plus a key revocation signature (reason 0), as GnuPG and sq pre-generate it.
- **Randomness.** Key generation, session keys, encryption and v6 signature salts use the operating system's RNG
  (`getrandom(2)` with no flags, through `rand_core`'s `OsRng`). v4 signatures need none.

## Security model

- **Input is hostile** on the keyless side: the message, signatures and certificates. Plaintext is read through the
  64 MiB cap and released only after SEIPD v1's MDC (read to the end) or the AEAD tag checks out. SED is refused
  before decryption on both sides (EFAIL); compressed data is unwrapped at most two levels deep.
- **The split.** `keyed::unwrap` stops at the first packet after the session-key packets: rPGP parses the PKESKs with
  the key, never the encrypted payload. The keyless functions take no key type at all. Process isolation is the
  caller's: put each half in its own process, give the keyed one no network, and pass only the session key between
  them. The library makes no system calls of its own and needs no file system or network, so each half fits a
  seccomp or Landlock sandbox with no rules beyond memory and its I/O descriptors.
- **Timing.** Two advisories in rPGP's pure-Rust backends are open with no fixed release on the `pgp` 0.21 line:
  RUSTSEC-2023-0071 (rsa, Marvin) and RUSTSEC-2026-0387 (crypto-bigint 0.5). Both are timing side channels in
  secret-key arithmetic, which only the keyed half does. They are ignored in `deny.toml` on that basis: a local,
  user-triggered, one-operation process with no network gives an attacker no timing oracle. A caller that unwraps on
  demand for remote parties must not rely on this.
- **No `unsafe`** (`unsafe_code = "forbid"` in the crate lints). A panic is an rPGP or library bug: run each half in a
  process you can afford to lose.
- **Dependencies** are pinned by `Cargo.lock` and every gate uses `--locked`. Licences are permissive; `bzip2-1.0.6`
  (libbz2-rs-sys, through rPGP's `bzip2` feature) is listed in `deny.toml`.

## Tests

- Unit tests are in `src/` (packet scan, MPI re-encoder).
- `tests/split.rs`: the split flow on real fixtures, the SED refusal before any key is parsed, tampered SEIPD, ZLIB
  and BZip2 decompression bombs, BZip2 decryption, key import with a passphrase and with a non-minimal MPI,
  certificate info, and the stable discriminants.
- `tests/corpus.rs` runs every fixture of `tests/corpus/eml` (48 messages from GnuPG 2.4.7 and 2.4.9, RNP 0.17.1,
  sq 1.3.1, EFAIL and signature-spoofing reconstructions) through the library with the test keys in
  `tests/corpus/keys`, and checks each outcome against a fixed table.
- `tests/send.rs`: signing (determinism of v4 signatures, v6 salts, intended recipients, refusals, corrupted secrets),
  key generation and its revocation certificate, renewal (expiry moved, protection kept, signing subkeys), encryption
  round trips, and the GnuPG vectors of `tests/corpus/send` (see its README.txt). Fuzz findings are kept in
  `tests/corpus/fuzz/<target>` with a test, and as `regress-*` seeds of the target.
- `fuzz/` holds three cargo-fuzz targets and their seed corpora: `packets` (structural scan, keyless decrypt, every
  verify, cert info), `import_key` (the MPI re-encoder's invariants and the whole import) and `send` (signing with and
  renewing arbitrary secret keys, encryption to arbitrary certificates, the `data_is_message` input).

The secret keys under `tests/corpus/keys` are throwaway test keys generated for the corpus; they protect nothing.

## Gates

Every check runs locally, in a pinned toolchain container (`tools/container/Dockerfile`: Rust 1.93.1 by digest, plus
cargo-fuzz 0.13.2 and cargo-deny 0.20.2):

```sh
tools/container.sh tools/gate.sh            # fmt, clippy, test, fuzz, audit
tools/container.sh tools/gate.sh test       # one job
FUZZ_SECONDS=600 tools/container.sh tools/gate.sh fuzz
```

| Job | What |
|---|---|
| `fmt` | `cargo fmt --check` of the crate and the fuzz harness |
| `clippy` | `cargo clippy --locked --all-targets -D warnings` of both |
| `test` | `cargo test --locked --release` |
| `fuzz` | every cargo-fuzz target for `FUZZ_SECONDS` (default 60), built with AddressSanitizer |
| `audit` | `cargo deny check`: advisories, licences, bans, sources |

The library ships no binaries, so there is no release artifact to reproduce. Consumers pin a commit.

`.github/workflows/` mirrors the gate for when the repository is hosted. `checks.yml` is a cheap check on every push.
`ci.yml` runs the full gate on tags and on manual dispatch.

## Licence

MIT, see `LICENSE`.
