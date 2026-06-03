//! SEC1 / X9.63 uncompressed P-256 point encoding.
//!
//! The keyvault exchanges P-256 public keys as the 65-byte uncompressed form
//! `0x04 || X(32) || Y(32)` — exactly CryptoKit's `x963Representation` and what
//! `wrap.py` consumes — so both the helper's own public key and the peer key
//! handed to ECDH cross the boundary in this shape.

/// Length of an uncompressed SEC1 P-256 point (`0x04 || X || Y`).
pub const UNCOMPRESSED_LEN: usize = 65;
/// Length of a single P-256 coordinate.
pub const COORD_LEN: usize = 32;
/// Leading byte marking an uncompressed point.
pub const PREFIX_UNCOMPRESSED: u8 = 0x04;

/// Error decoding an uncompressed SEC1 point.
#[derive(Debug, PartialEq, Eq)]
pub enum Sec1Error {
    /// Wrong total length (expected 65).
    BadLength(usize),
    /// Leading byte was not `0x04` (compressed / hybrid / malformed).
    BadPrefix(u8),
}

/// Encode `(x, y)` as a 65-byte uncompressed SEC1 point.
pub fn encode_point(x: &[u8; COORD_LEN], y: &[u8; COORD_LEN]) -> [u8; UNCOMPRESSED_LEN] {
    let mut out = [0u8; UNCOMPRESSED_LEN];
    out[0] = PREFIX_UNCOMPRESSED;
    out[1..1 + COORD_LEN].copy_from_slice(x);
    out[1 + COORD_LEN..].copy_from_slice(y);
    out
}

/// Decode a 65-byte uncompressed SEC1 point into its `(x, y)` coordinates.
///
/// Validates the structural form only (length + `0x04` prefix); on-curve
/// membership is enforced TPM-side by `ECDH_ZGen`, which rejects points off
/// the curve.
pub fn decode_point(bytes: &[u8]) -> Result<([u8; COORD_LEN], [u8; COORD_LEN]), Sec1Error> {
    if bytes.len() != UNCOMPRESSED_LEN {
        return Err(Sec1Error::BadLength(bytes.len()));
    }
    if bytes[0] != PREFIX_UNCOMPRESSED {
        return Err(Sec1Error::BadPrefix(bytes[0]));
    }
    let mut x = [0u8; COORD_LEN];
    let mut y = [0u8; COORD_LEN];
    x.copy_from_slice(&bytes[1..1 + COORD_LEN]);
    y.copy_from_slice(&bytes[1 + COORD_LEN..]);
    Ok((x, y))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_lays_out_prefix_x_y() {
        let x = [0x11u8; 32];
        let y = [0x22u8; 32];
        let out = encode_point(&x, &y);
        assert_eq!(out[0], 0x04);
        assert_eq!(&out[1..33], &x[..]);
        assert_eq!(&out[33..], &y[..]);
    }

    #[test]
    fn encode_then_decode_round_trips() {
        let x: [u8; 32] = core::array::from_fn(|i| i as u8);
        let y: [u8; 32] = core::array::from_fn(|i| (255 - i) as u8);
        let encoded = encode_point(&x, &y);
        let (dx, dy) = decode_point(&encoded).unwrap();
        assert_eq!(dx, x);
        assert_eq!(dy, y);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert_eq!(decode_point(&[0x04; 64]), Err(Sec1Error::BadLength(64)));
        assert_eq!(decode_point(&[0x04; 66]), Err(Sec1Error::BadLength(66)));
        assert_eq!(decode_point(&[]), Err(Sec1Error::BadLength(0)));
    }

    #[test]
    fn decode_rejects_compressed_prefix() {
        let mut compressed = [0u8; 65];
        compressed[0] = 0x02;
        assert_eq!(decode_point(&compressed), Err(Sec1Error::BadPrefix(0x02)));
    }
}
