//! Abstraction over the content to be signed.

use crate::Hash;
use crate::always::*;
use core::ops::Range;
use std::time::SystemTime;

const TIME_RANGE: Range<usize> = 0..TIME;
const STATE_HASH_RANGE: Range<usize> = TIME..TIME + DIGEST;

fn system_time() -> u64 {
    let now = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => 0,
    };
    now.try_into().unwrap()
}

/// Content to be included in block and signed.
///
/// # Examples
///
/// ```
/// use zf_zebrachain::{Hash, Payload, PAYLOAD};
///
/// // A payload includes a state hash, which you can create like this:
/// let state_hash = Hash::compute(b"My first ZebraChain signature");
///
/// // A payload also includes a u64 timestamp (nanoseconds since the Unix Epoch). You can
/// // provide the timestamp as the first argument to Payload::new() like this:
/// let payload = Payload::new(123456789, state_hash);
///
/// // Or you can have the timestamp automatically created for you using
/// // Payload::new_time_stamped() like this:
/// let payload = Payload::new_time_stamped(state_hash);
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Payload {
    /// Timestamp (nanoseconds since the UNIX Epoch).
    pub time: u64,

    /// Hash of top-level state object in a hypothetical object store.
    pub state_hash: Hash,
}

impl Payload {
    /// Create a new payload.
    pub fn new(time: u64, state_hash: Hash) -> Self {
        Self { time, state_hash }
    }

    /// Create a payload from the provided hash, but generate the timestamp automatically.
    pub fn new_time_stamped(state_hash: Hash) -> Self {
        let time = system_time();
        Self::new(time, state_hash)
    }

    /// Extract payload from buffer.
    pub fn from_buf(buf: &[u8]) -> Self {
        assert_eq!(buf.len(), PAYLOAD);
        Self {
            time: u64::from_le_bytes(buf[TIME_RANGE].try_into().unwrap()),
            state_hash: Hash::from_slice(&buf[STATE_HASH_RANGE]).unwrap(),
        }
    }

    /// Write payload into buffer.
    pub fn write_to_buf(&self, buf: &mut [u8]) {
        assert_eq!(buf.len(), PAYLOAD);
        buf[TIME_RANGE].copy_from_slice(&self.time.to_le_bytes());
        buf[STATE_HASH_RANGE].copy_from_slice(self.state_hash.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhelpers::{random_hash, random_u64};
    use getrandom;

    #[test]
    fn test_payload_new_time_stamped() {
        let state_hash = Hash::compute(b"yo dawg");
        let payload = Payload::new_time_stamped(state_hash);
        assert_eq!(payload.state_hash, state_hash);
        assert!(payload.time > 0);
    }

    #[test]
    fn test_payload_from_buf() {
        let buf = [69; PAYLOAD];
        let payload = Payload::from_buf(&buf);
        assert_eq!(payload.state_hash, Hash::from_bytes([69; DIGEST]));
        assert_eq!(payload.time, 4991471925827290437);
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
                58, 1, 0, 0, 0, 0, 0, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
                42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
                42, 42, 42, 42, 42, 42, 42, 42, 42, 42
            ]
        );
    }

    #[test]
    fn test_payload_roundtrip() {
        let mut buf = [0; PAYLOAD];
        for _ in 0..420 {
            let time = random_u64();
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
