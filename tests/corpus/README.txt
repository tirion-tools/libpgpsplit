OpenPGP test fixtures (synthetic; every key here is a throwaway test key).

eml/      48 messages. gpgdeb-*: GnuPG 2.4.7 (Debian 13); gpgarch-*: GnuPG 2.4.9 (Arch, upstream); rnp-*: RNP 0.17.1;
          sq-*: sq 1.3.1 (v4 and RFC 9580 v6 keys, SEIPDv2); efail-pgp-*: EFAIL reconstructions (MDC stripped to SED,
          SEIPD ciphertext modified, direct exfiltration wrappers); spoof-*: signature-spoofing reconstructions
          (cleartext Hash: header injection, MIME wrapping, partial inline signatures, unknown key, changed content,
          surreptitious forwarding); gnupg-nonminimal-mpi-key: see keys/gnupg-zed.README.
keys/     the secret keys and certificates the messages use. gpg*-pat.sec.asc are protected with the passphrase
          "correct horse"; the others are unprotected.
bomb-64mib.pgp        an unencrypted ZLIB-compressed message whose literal data inflates past 64 MiB.
bomb-bzip2-80mib.pgp  the same with BZip2 (114 bytes, 80 MiB).
bzip2-dana.pgp        a BZip2-compressed message encrypted to gpgdeb-dana, as older PGP versions write it.

Tool versions of the Debian run: gnupg 2.4.7-21+deb13u1, rnp/librnp0 0.17.1-1+b1, sq 1.3.1-2+b2.
