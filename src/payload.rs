//! Abstraction over the content to be signed.

use crate::always::*;
use crate::hashing::Hash;
use std::ops::Range;

const TIME_RANGE: Range<usize> = 0..TIME;
const STATE_HASH_RANGE: Range<usize> = TIME..TIME + DIGEST;

/// Content to be included in block and signed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Payload {
    /// Timestamp.
    pub time: u128,

    /// Hash of top-level state object in a hypothetical object store.
    pub state_hash: Hash,
}

impl Payload {
    /// Create a new payload.
    pub fn new(time: u128, state_hash: Hash) -> Self {
        Self { time, state_hash }
    }

    /// Extract payload from buffer.
    pub fn from_buf(buf: &[u8]) -> Self {
        assert_eq!(buf.len(), PAYLOAD);
        Self {
            time: get_u128(buf, TIME_RANGE),
            state_hash: get_hash(buf, STATE_HASH_RANGE),
        }
    }

    /// Write payload into buffer.
    pub fn write_to_buf(&self, buf: &mut [u8]) {
        assert_eq!(buf.len(), PAYLOAD);
        set_u128(buf, TIME_RANGE, self.time);
        set_hash(buf, STATE_HASH_RANGE, &self.state_hash);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhelpers::{random_hash, random_u128};
    use getrandom;

    #[test]
    fn test_payload_from_buf() {
        let buf = [69; PAYLOAD];
        let payload = Payload::from_buf(&buf);
        assert_eq!(payload.state_hash, Hash::from_bytes([69; DIGEST]));
        assert_eq!(payload.time, 92076405166842172466560187893301986629);
    }

    #[test]
    fn test_payload_write_to_buf() {
        let time = 314;
        let state_hash = Hash::from_bytes([42; DIGEST]);
        let payload = Payload::new(time, state_hash);
        let mut buf = [0; PAYLOAD];
        payload.write_to_buf(&mut buf);
        assert_eq!(
            buf,
            [
                58, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42, 42, 42, 42, 42, 42, 42, 42,
                42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
                42, 42, 42
            ]
        );
    }

    #[test]
    fn test_payload_roundtrip() {
        let mut buf = [0; PAYLOAD];
        for _ in 0..420 {
            let time = random_u128();
            let state_hash = random_hash();
            let payload = Payload::new(time, state_hash);
            payload.write_to_buf(&mut buf);
            let payload = Payload::from_buf(&buf);
            assert_eq!(payload.time, time);
            assert_eq!(payload.state_hash, state_hash);
        }
    }

    #[test]
    fn test_payload_roundtrip_buffer() {
        for _ in 0..420 {
            let mut buf = [0; PAYLOAD];
            getrandom::fill(&mut buf).unwrap();
            let payload = Payload::from_buf(&buf);
            let mut buf2 = [0; PAYLOAD];
            assert_ne!(buf, buf2);
            payload.write_to_buf(&mut buf2);
            assert_eq!(buf, buf2);
        }
    }
}
