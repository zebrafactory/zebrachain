//! Abstraction over the content to be signed.

use crate::always::*;
use crate::{Hash, RootError};
use core::ops::Range;
use std::collections::HashSet;
use std::time::SystemTime;
use subtle::ConstantTimeEq;

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

#[derive(Debug, PartialEq)]
pub struct Permission {
    chains: HashSet<Hash>,
}

impl Permission {
    pub fn new() -> Self {
        Self {
            chains: HashSet::new(),
        }
    }

    pub fn needed_size(&self) -> usize {
        self.chains.len() * DIGEST
    }

    pub fn insert(&mut self, chain_hash: Hash) -> Result<(), RootError> {
        if self.chains.insert(chain_hash) {
            Ok(())
        } else {
            Err(RootError::Duplicate)
        }
    }

    pub fn is_allowed(&self, chain_hash: &Hash) -> bool {
        self.chains.contains(chain_hash)
    }

    pub fn from_buf(buf: &[u8]) -> Result<Self, RootError> {
        if buf.is_empty() {
            Err(RootError::EmptyBuffer)
        } else if !buf.len().is_multiple_of(DIGEST) {
            Err(RootError::BufferLength)
        } else {
            let mut permission = Self::new();
            let mut offset = 0;
            for _ in 0..buf.len() / DIGEST {
                let chain_hash = Hash::from_slice(&buf[offset..offset + DIGEST]).unwrap();
                offset += DIGEST;
                permission.insert(chain_hash)?;
            }
            Ok(permission)
        }
    }

    pub fn write_to_buf(&self, buf: &mut [u8]) -> Result<(), RootError> {
        if self.chains.is_empty() {
            Err(RootError::Empty)
        } else if buf.is_empty() {
            Err(RootError::EmptyBuffer)
        } else if buf.len() != self.needed_size() {
            Err(RootError::BufferLength)
        } else {
            let mut chains = Vec::from_iter(&self.chains);
            chains.sort();
            let mut offset = 0;
            for chain_hash in &chains {
                buf[offset..offset + DIGEST].copy_from_slice(chain_hash.as_bytes());
                offset += DIGEST;
            }
            Ok(())
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Root {
    pub hash: Hash,
    pub permission: Permission,
    pub previous_hash: Hash,
}

impl Root {
    pub fn needed_size(&self) -> usize {
        self.permission.needed_size() + DIGEST * 2
    }

    pub fn from_buf(buf: &[u8]) -> Result<Self, RootError> {
        if !buf.len().is_multiple_of(DIGEST) || buf.len() < DIGEST * 3 {
            Err(RootError::BufferLength)
        } else {
            let hash = Hash::from_slice(&buf[0..DIGEST]).unwrap();
            if hash.ct_ne(&Hash::compute(&buf[DIGEST..])).into() {
                Err(RootError::Hash)
            } else {
                let permission = Permission::from_buf(&buf[DIGEST..buf.len() - DIGEST])?;
                let previous_hash = Hash::from_slice(&buf[buf.len() - DIGEST..]).unwrap();
                Ok(Self {
                    hash,
                    permission,
                    previous_hash,
                })
            }
        }
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

    #[test]
    fn test_permission_new() {
        let permission = Permission::new();
        assert!(permission.chains.is_empty());
        assert_eq!(permission.needed_size(), 0);
    }

    #[test]
    fn test_permission_insert_and_is_allowed() {
        let mut permission = Permission::new();

        let chain0_hash = random_hash();
        assert!(!permission.is_allowed(&chain0_hash));
        assert_eq!(permission.insert(chain0_hash.clone()), Ok(()));
        assert!(permission.is_allowed(&chain0_hash));
        assert_eq!(
            permission.insert(chain0_hash.clone()),
            Err(RootError::Duplicate)
        );
        assert_eq!(permission.chains.len(), 1);
        assert_eq!(permission.needed_size(), DIGEST);

        let chain1_hash = random_hash();
        assert!(!permission.is_allowed(&chain1_hash));
        assert_eq!(permission.insert(chain1_hash.clone()), Ok(()));
        assert!(permission.is_allowed(&chain1_hash));
        assert_eq!(
            permission.insert(chain1_hash.clone()),
            Err(RootError::Duplicate)
        );
        assert!(permission.is_allowed(&chain0_hash));
        assert_eq!(permission.chains.len(), 2);
        assert_eq!(permission.needed_size(), DIGEST * 2);
    }

    #[test]
    fn test_permission_from_buf() {
        assert_eq!(Permission::from_buf(&[69; 0]), Err(RootError::EmptyBuffer));
        assert_eq!(Permission::from_buf(&[69; 1]), Err(RootError::BufferLength));
        assert_eq!(
            Permission::from_buf(&[69; DIGEST - 1]),
            Err(RootError::BufferLength)
        );
        assert_eq!(
            Permission::from_buf(&[69; DIGEST + 1]),
            Err(RootError::BufferLength)
        );

        let permission = Permission::from_buf(&[69; DIGEST]).unwrap();
        let chain_hash = Hash::from_bytes([69; DIGEST]);
        assert_eq!(permission.chains.len(), 1);
        assert!(permission.is_allowed(&chain_hash));

        assert_eq!(
            Permission::from_buf(&[69; DIGEST * 2 - 1]),
            Err(RootError::BufferLength)
        );
        assert_eq!(
            Permission::from_buf(&[69; DIGEST * 2]),
            Err(RootError::Duplicate)
        );
        assert_eq!(
            Permission::from_buf(&[69; DIGEST * 2 + 1]),
            Err(RootError::BufferLength)
        );

        let mut buf = [42; DIGEST * 2];
        buf[DIGEST..DIGEST * 2].copy_from_slice(&[69; DIGEST]);
        let permission = Permission::from_buf(&buf).unwrap();
        assert_eq!(permission.chains.len(), 2);
        assert!(!permission.is_allowed(&Hash::from_bytes([41; DIGEST])));
        assert!(permission.is_allowed(&Hash::from_bytes([42; DIGEST])));
        assert!(permission.is_allowed(&Hash::from_bytes([69; DIGEST])));
        assert!(!permission.is_allowed(&Hash::from_bytes([70; DIGEST])));
    }

    #[test]
    fn test_permission_write_to_buf() {
        let mut buf = [0; DIGEST];
        let mut permission = Permission::new();
        assert_eq!(permission.write_to_buf(&mut buf), Err(RootError::Empty));
        let chain0_hash = random_hash();
        permission.insert(chain0_hash.clone()).unwrap();
        assert_eq!(
            permission.write_to_buf(&mut [0; 0]),
            Err(RootError::EmptyBuffer)
        );
        assert_eq!(
            permission.write_to_buf(&mut [0; 1]),
            Err(RootError::BufferLength)
        );
        assert_eq!(
            permission.write_to_buf(&mut [0; DIGEST - 1]),
            Err(RootError::BufferLength)
        );
        assert_eq!(
            permission.write_to_buf(&mut [0; DIGEST + 1]),
            Err(RootError::BufferLength)
        );
        permission.write_to_buf(&mut buf).unwrap();
        assert_eq!(&buf, chain0_hash.as_bytes());

        let mut buf = [0; DIGEST * 2];
        let chain1_hash = random_hash();
        permission.insert(chain1_hash.clone()).unwrap();
        assert_eq!(
            permission.write_to_buf(&mut [0; DIGEST * 2 - 1]),
            Err(RootError::BufferLength)
        );
        assert_eq!(
            permission.write_to_buf(&mut [0; DIGEST * 2 + 1]),
            Err(RootError::BufferLength)
        );
        permission.write_to_buf(&mut buf).unwrap();
        if chain0_hash < chain1_hash {
            assert_eq!(&buf[0..DIGEST], chain0_hash.as_bytes());
            assert_eq!(&buf[DIGEST..DIGEST * 2], chain1_hash.as_bytes());
        } else {
            assert_eq!(&buf[0..DIGEST], chain1_hash.as_bytes());
            assert_eq!(&buf[DIGEST..DIGEST * 2], chain0_hash.as_bytes());
        }
    }

    #[test]
    fn test_root_from_buf() {
        assert_eq!(Root::from_buf(&[42; 0]), Err(RootError::BufferLength));
        assert_eq!(Root::from_buf(&[42; 1]), Err(RootError::BufferLength));
        assert_eq!(
            Root::from_buf(&[42; DIGEST * 3 - 1]),
            Err(RootError::BufferLength)
        );
        assert_eq!(
            Root::from_buf(&[42; DIGEST * 3 + 1]),
            Err(RootError::BufferLength)
        );
        assert_eq!(
            Root::from_buf(&[42; DIGEST * 4 - 1]),
            Err(RootError::BufferLength)
        );
        assert_eq!(
            Root::from_buf(&[42; DIGEST * 4 + 1]),
            Err(RootError::BufferLength)
        );
        assert_eq!(Root::from_buf(&[42; DIGEST * 3]), Err(RootError::Hash));

        let mut buf = [42; DIGEST * 4];
        let hash = Hash::compute(&buf[DIGEST..]);
        buf[0..DIGEST].copy_from_slice(hash.as_bytes());
        assert_eq!(Root::from_buf(&buf), Err(RootError::Duplicate));

        let mut buf = [42; DIGEST * 3];
        let hash = Hash::compute(&buf[DIGEST..]);
        buf[0..DIGEST].copy_from_slice(hash.as_bytes());
        let root = Root::from_buf(&buf).unwrap();
        assert_eq!(hash, root.hash);

        let mut buf = [0; DIGEST * 3];
        let chain0_hash = random_hash();
        let previous_hash = random_hash();
        buf[DIGEST..DIGEST * 2].copy_from_slice(chain0_hash.as_bytes());
        buf[DIGEST * 2..DIGEST * 3].copy_from_slice(previous_hash.as_bytes());
        let root0_hash = Hash::compute(&buf[DIGEST..]);
        buf[0..DIGEST].copy_from_slice(root0_hash.as_bytes());
        let root0 = Root::from_buf(&buf).unwrap();
        assert_eq!(root0.hash, root0_hash);
        assert!(root0.permission.is_allowed(&chain0_hash));
        assert_eq!(root0.previous_hash, previous_hash);

        let chain1_hash = random_hash();
        assert!(!root0.permission.is_allowed(&chain1_hash));

        let mut buf = [0; DIGEST * 4];
        buf[DIGEST..DIGEST * 2].copy_from_slice(chain0_hash.as_bytes());
        buf[DIGEST * 2..DIGEST * 3].copy_from_slice(chain1_hash.as_bytes());
        buf[DIGEST * 3..DIGEST * 4].copy_from_slice(root0.hash.as_bytes());
        let root1_hash = Hash::compute(&buf[DIGEST..]);
        buf[0..DIGEST].copy_from_slice(root1_hash.as_bytes());
        let root1 = Root::from_buf(&buf).unwrap();
        assert_eq!(root1.hash, root1_hash);
        assert!(root1.permission.is_allowed(&chain0_hash));
        assert!(root1.permission.is_allowed(&chain1_hash));
        assert_eq!(root1.previous_hash, root0.hash);
    }
}
