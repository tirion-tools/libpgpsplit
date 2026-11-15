//! GnuPG writes some unprotected v4 secret MPIs non-minimally (a 256-bit length over a value whose first byte is
//! 0x00: about 1 in 256 Ed25519 keys), with the checksum over those bytes. RFC 9580 §3.2 MPIs start at the most
//! significant non-zero bit; rPGP refuses such keys ("Invalid checksum"). Key import re-encodes the secret MPIs of
//! unprotected (S2K usage 0) v4 secret-key packets minimally and recomputes the checksum; everything else passes
//! through unchanged.

fn mpi_end(b: &[u8], at: usize) -> Option<usize> {
    let bits = u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?) as usize;
    let end = at + 2 + bits.div_ceil(8);
    (end <= b.len()).then_some(end)
}

/// End of the public part of a v4 key packet body (version, created(4), algo, algorithm fields).
fn public_end(b: &[u8]) -> Option<usize> {
    if b.first() != Some(&4) {
        return None;
    }
    let mut at = 6;
    let mpis = |n: usize, mut at: usize| -> Option<usize> {
        for _ in 0..n {
            at = mpi_end(b, at)?;
        }
        Some(at)
    };
    match *b.get(5)? {
        1..=3 => mpis(2, at),
        16 | 20 => mpis(3, at),
        17 => mpis(4, at),
        19 | 22 => {
            at += 1 + *b.get(at)? as usize;
            mpis(1, at)
        }
        18 => {
            at += 1 + *b.get(at)? as usize;
            at = mpi_end(b, at)?;
            Some(at + 1 + *b.get(at)? as usize)
        }
        _ => None,
    }
}

/// Canonical secret MPIs of every unprotected v4 secret key/subkey packet in `bin` (binary packets). Malformed or
/// unsupported framing returns the input unchanged; the parser then decides.
pub fn canonical_secret_mpis(bin: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(bin.len());
    let mut i = 0;
    while i < bin.len() {
        let h = bin[i];
        // only definite lengths are handled; anything else: unchanged
        let (tag, hl, len) = if h & 0xC0 == 0xC0 {
            let tag = h & 0x3f;
            match bin.get(i + 1).copied() {
                Some(l @ 0..=191) => (tag, 2, l as usize),
                Some(l @ 192..=223) => match bin.get(i + 2) {
                    Some(&l1) => (tag, 3, ((l as usize - 192) << 8) + l1 as usize + 192),
                    None => return bin,
                },
                Some(255) => match bin.get(i + 2..i + 6) {
                    Some(b) => (
                        tag,
                        6,
                        u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize,
                    ),
                    None => return bin,
                },
                _ => return bin,
            }
        } else if h & 0xC0 == 0x80 {
            let tag = (h >> 2) & 0x0f;
            match h & 3 {
                0 => match bin.get(i + 1) {
                    Some(&l) => (tag, 2, l as usize),
                    None => return bin,
                },
                1 => match bin.get(i + 1..i + 3) {
                    Some(b) => (tag, 3, u16::from_be_bytes([b[0], b[1]]) as usize),
                    None => return bin,
                },
                2 => match bin.get(i + 1..i + 5) {
                    Some(b) => (
                        tag,
                        5,
                        u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize,
                    ),
                    None => return bin,
                },
                _ => return bin,
            }
        } else {
            return bin;
        };
        let Some(end) = (i + hl).checked_add(len) else {
            return bin;
        };
        let Some(body) = bin.get(i + hl..end) else {
            return bin;
        };
        let mut new_body = None;
        if (tag == 5 || tag == 7)
            && let Some(pe) = public_end(body)
            && body.get(pe) == Some(&0)
            && body.len() >= pe + 3
        {
            let secret = &body[pe + 1..body.len() - 2];
            let mut canon = Vec::with_capacity(secret.len());
            let mut at = 0;
            let mut changed = false;
            while at < secret.len() {
                let Some(end) = mpi_end(secret, at) else {
                    break;
                };
                let v = &secret[at + 2..end];
                let nz = v.iter().position(|&x| x != 0).unwrap_or(v.len());
                let v = &v[nz..];
                let bits = if v.is_empty() {
                    0
                } else {
                    v.len() * 8 - v[0].leading_zeros() as usize
                };
                changed |= bits != u16::from_be_bytes([secret[at], secret[at + 1]]) as usize;
                canon.extend_from_slice(&(bits as u16).to_be_bytes());
                canon.extend_from_slice(v);
                at = end;
            }
            if changed && at == secret.len() {
                let sum: u16 = canon.iter().fold(0u16, |a, &x| a.wrapping_add(x as u16));
                let mut nb = body[..=pe].to_vec();
                nb.extend_from_slice(&canon);
                nb.extend_from_slice(&sum.to_be_bytes());
                new_body = Some(nb);
            }
        }
        match new_body {
            Some(nb) => {
                // re-emitted as a new-format packet with a 4-octet length
                out.push(0xC0 | tag);
                out.push(255);
                out.extend_from_slice(&(nb.len() as u32).to_be_bytes());
                out.extend_from_slice(&nb);
            }
            None => out.extend_from_slice(&bin[i..end]),
        }
        i = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_passes_through_unchanged() {
        for b in [
            vec![],
            vec![0x00],
            vec![0xC5],
            vec![0xC5, 0xFF, 0, 0],
            vec![0x94, 0x10, 1, 2],
        ] {
            assert_eq!(canonical_secret_mpis(b.clone()), b);
        }
    }

    #[test]
    fn non_minimal_mpi_is_re_encoded_with_its_checksum() {
        // v4 Ed25519 (algo 22) secret key packet: public part (oid len 1 + 1 byte oid, one 8-bit MPI), S2K usage 0,
        // secret MPI written as 16 bits over 0x00 0x7F.
        let mut body = vec![4, 0, 0, 0, 0, 22, 1, 0x2B, 0, 8, 0xAA, 0];
        body.extend_from_slice(&[0, 16, 0x00, 0x7F]);
        body.extend_from_slice(&(0x10u16 + 0x7F).to_be_bytes());
        let mut pkt = vec![0xC5, body.len() as u8];
        pkt.extend_from_slice(&body);
        let out = canonical_secret_mpis(pkt);
        let nb = &out[6..];
        assert_eq!(&nb[12..15], &[0, 7, 0x7F]);
        assert_eq!(&nb[15..], &(7u16 + 0x7F).to_be_bytes());
    }
}
