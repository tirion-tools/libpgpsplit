//! Shared by both halves: armor detection, bounded dearmoring and the structural packet scan.

use std::io::{BufReader, Read};

use crate::{Container, MAX_PLAINTEXT, Reason, Refusal, e};

/// Most top-level packets [`scan`] looks at.
const MAX_SCANNED: usize = 64;

pub(crate) fn is_armored(d: &[u8]) -> bool {
    let t = d
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .map(|i| &d[i..])
        .unwrap_or(d);
    t.starts_with(b"-----BEGIN PGP")
}

pub(crate) fn dearmor(d: &[u8]) -> Result<Vec<u8>, Refusal> {
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
/// structural scan the SED refusal relies on; it is fuzzed (fuzz/fuzz_targets/packets.rs).
pub(crate) fn scan(bin: &[u8]) -> Vec<(u8, Option<u8>)> {
    let mut out = vec![];
    let mut i = 0usize;
    while i < bin.len() && out.len() < MAX_SCANNED {
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

pub(crate) fn container(tags: &[(u8, Option<u8>)]) -> Container {
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

/// Malleable SED is never decrypted (EFAIL); both halves refuse it before anything else is done.
pub(crate) fn refuse_sed(cont: Container) -> Result<(), Refusal> {
    if cont == Container::Sed {
        return Err(Refusal::new(
            Reason::NoIntegrity,
            "Symmetrically Encrypted Data packet (no MDC)",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_reads_both_header_formats_and_stops_at_partial_lengths() {
        // old-format PKESK (tag 1, one-octet length 2), new-format SEIPD v1 (tag 18, partial length)
        let bin = [0x84, 2, 3, 0, 0xD2, 0xE0, 1, 9, 9];
        assert_eq!(scan(&bin), vec![(1, None), (18, Some(1))]);
        assert_eq!(container(&scan(&bin)), Container::SeipdV1);
        // SED (tag 9) after a PKESK
        assert_eq!(container(&scan(&[0x84, 0, 0xC9, 1, 0])), Container::Sed);
        // OCB Encrypted Data (tag 20); SEIPD v2
        assert_eq!(container(&scan(&[0xD4, 1, 1])), Container::Ocbed);
        assert_eq!(container(&scan(&[0xD2, 1, 2])), Container::SeipdV2);
        assert_eq!(container(&scan(&[0xD2, 1, 7])), Container::Unknown);
        assert_eq!(container(&scan(b"not a packet")), Container::None);
    }

    #[test]
    fn scan_is_bounded() {
        let many = [0xC2, 0].repeat(1000);
        assert_eq!(scan(&many).len(), MAX_SCANNED);
        // a length past the end stops the scan instead of overflowing
        assert_eq!(scan(&[0xC2, 255, 0xFF, 0xFF, 0xFF, 0xFF, 0xC2, 0]).len(), 1);
    }
}
