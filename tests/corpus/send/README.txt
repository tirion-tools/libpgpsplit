Send-side vectors, cross-checked with an independent implementation: GnuPG 2.4.8 (the Debian gnupg package of
Graphein's build image graphein-build:a93cb27468e9485e), 2026-11-16.

data.txt               the signed and encrypted bytes (a CRLF MIME entity).
dana-detached.asc      keyed::sign(keys/gpgdeb-dana.sec.asc, data.txt, Detached, [], 1794787200): Ed25519, SHA-256.
rex-detached.asc       the same with keys/gpgdeb-rex.sec.asc: RSA-3072 PKCS#1 v1.5, SHA-256.
dana-inline.pgp        keyed::sign(gpgdeb-dana, data.txt, Inline, [fingerprint of gpgdeb-pat], 1794787200).
generated.{sec,pub}.pgp, generated.rev.asc
                       keyed::generate_key(["Vec Tor <vector@example.test>"], 1794787200, Some(94608000)): a throwaway
                       test key (it protects nothing), its certificate and its revocation certificate.
gnupg-to-generated.asc gpg -u dana@gpgdeb.test -r <generated> --sign --encrypt data.txt
gnupg-by-generated.asc gpg -u <generated> --detach-sign data.txt (GnuPG signing with the generated secret key)

GnuPG's results when they were made: `gpg --verify` printed VALIDSIG for dana-detached.asc, rex-detached.asc and
dana-inline.pgp (its literal data is data.txt byte for byte); it imported generated.sec.pgp with the primary key
"scESC" and the subkey "e", both expiring at 1889395200 (created + 3 years); it decrypted gnupg-to-generated.asc with
the generated key (DECRYPTION_OKAY); importing generated.rev.asc marked the key revoked ("r").

tests/send.rs checks that the library still makes the three signatures byte for byte (v4 signatures are a function of
key, data and creation time), and that it decrypts and verifies GnuPG's two files with the generated key. The live
GnuPG round trips of the helper (encryption both ways, renewal, revocation) are Graphein's
helpers/graphein-crypto/tests/gnupg.rs.
