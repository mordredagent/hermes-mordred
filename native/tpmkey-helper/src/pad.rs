//! Fixed-width left-padding for ECDH Z coordinates.
//!
//! TPM `ECDH_ZGen` returns the shared point's X coordinate as a big-endian
//! integer that may have its leading zero byte(s) stripped (a `TPM2B` is
//! length-prefixed, not fixed-width). The keyvault's WMK wire format feeds a
//! *fixed* 32-byte X coordinate into HKDF — identical to
//! `SecKeyCopyKeyExchangeResult` and the software fallback — so a short Z must
//! be left-padded back to 32 bytes. Getting this wrong corrupts the wrapping
//! key only for the ~1/256 of keys whose X has a leading zero byte, so it is
//! covered here exhaustively rather than discovered in the field.

/// Error returned when an input is too long to fit a 32-byte field.
#[derive(Debug, PartialEq, Eq)]
pub struct PadError {
    /// The offending input length (always `> 32`).
    pub len: usize,
}

/// Left-pad `input` with leading zero bytes to exactly 32 bytes.
///
/// Returns [`PadError`] if `input` is longer than 32 bytes (an over-long Z
/// coordinate is never valid for P-256 and must not be silently truncated).
pub fn left_pad_32(input: &[u8]) -> Result<[u8; 32], PadError> {
    if input.len() > 32 {
        return Err(PadError { len: input.len() });
    }
    let mut out = [0u8; 32];
    out[32 - input.len()..].copy_from_slice(input);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_32_is_identity() {
        let input: Vec<u8> = (0..32).collect();
        let out = left_pad_32(&input).unwrap();
        assert_eq!(&out[..], &input[..]);
    }

    #[test]
    fn pads_short_input_on_the_left() {
        let out = left_pad_32(&[0xAA]).unwrap();
        let mut expected = [0u8; 32];
        expected[31] = 0xAA;
        assert_eq!(out, expected);
    }

    #[test]
    fn pads_31_bytes_with_single_leading_zero() {
        let input: Vec<u8> = (1..=31).collect();
        let out = left_pad_32(&input).unwrap();
        assert_eq!(out[0], 0x00);
        assert_eq!(&out[1..], &input[..]);
    }

    #[test]
    fn empty_input_is_all_zero() {
        assert_eq!(left_pad_32(&[]).unwrap(), [0u8; 32]);
    }

    #[test]
    fn reconstructs_leading_zero_coordinate() {
        // A real 32-byte X whose top byte is 0x00 is what the TPM would hand
        // back as 31 bytes; left-padding must rebuild the original value.
        let mut full = [0u8; 32];
        full[0] = 0x00;
        full[1] = 0x7F;
        full[31] = 0x01;
        let stripped = &full[1..]; // 31 bytes, as a TPM2B would carry it
        assert_eq!(left_pad_32(stripped).unwrap(), full);
    }

    #[test]
    fn rejects_over_long_input() {
        let too_long = vec![0u8; 33];
        assert_eq!(left_pad_32(&too_long), Err(PadError { len: 33 }));
    }
}
