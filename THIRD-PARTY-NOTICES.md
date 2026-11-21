# Third-party notices

The code in this repository is MIT-licensed (`LICENSE`, Copyright (c) 2026 Tirion) unless this file says otherwise.

## Bundled third-party code and data

None. The keys, messages and fuzz seeds in `tests/corpus/` and `fuzz/corpus/` are synthetic: throwaway test keys
generated for this repository with GnuPG, RNP and sq (see `tests/corpus/README.txt`), and messages made with them.
They protect nothing.

## Dependencies (not bundled)

Dependencies are not vendored: they are fetched at build time (Rust crates from crates.io, pinned in `Cargo.lock`) under their own licences, and the gate
checks their licences (`cargo deny`, `deny.toml`). Nothing from them is redistributed in this repository.

- [rPGP](https://github.com/rpgp/rpgp) (`pgp`, MIT or Apache-2.0); BZip2 through `libbz2-rs-sys` (bzip2-1.0.6
  licence, BSD-style).
