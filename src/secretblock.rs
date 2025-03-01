//! Wire format for secret seeds when written to nonvolatile storage.

use crate::always::*;
use crate::block::SigningRequest;
use crate::secretseed::Seed;
use blake3::{Hash, hash};
use std::io;

fn check_secretblock_buf(buf: &[u8]) {
    if buf.len() != SECRET_BLOCK {
        panic!("Need a {SECRET_BLOCK} byte slice; got {} bytes", buf.len());
    }
}

/// Expresses different error conditions hit when validating a [SecretBlock].
#[derive(Debug, PartialEq)]
pub enum SecretBlockError {
    /// Hash of block content does not match hash in block.
    Content,

    /// Block contains a bad seed where `secret == next_secret`.
    Seed,

    /// Block is out of sequence (`seed.secret != previous.next_secret`).
    SeedSequence,

    /// Hash in block does not match expected external value.
    Hash,

    /// Block index is wrong.
    Index,

    /// Previous hash in block does not match expected external value.
    PreviousHash,
}

impl SecretBlockError {
    // FIXME: Is there is a Rustier way of doing this? Feedback encouraged.
    pub fn to_io_error(&self) -> io::Error {
        io::Error::other(format!("SecretBlockError::{self:?}"))
    }
}

/// Alias for `Result<SecretBlock, SecretBlockError`.
pub type SecretBlockResult = Result<SecretBlock, SecretBlockError>;

/// Wire format for saving secret chain to nonvolatile storage.
#[derive(Debug, PartialEq, Clone)]
pub struct SecretBlock {
    pub block_hash: Hash,
    pub seed: Seed,
    pub request: SigningRequest,
    pub index: u64,
    pub previous_hash: Hash,
}

impl SecretBlock {
    pub fn open(buf: &[u8]) -> SecretBlockResult {
        check_secretblock_buf(buf);
        let computed_hash = hash(&buf[DIGEST..]);
        let block_hash = get_hash(buf, SEC_HASH_RANGE);
        let secret = get_hash(buf, SEC_SECRET_RANGE);
        let next_secret = get_hash(buf, SEC_NEXT_SECRET_RANGE);
        if computed_hash != block_hash {
            Err(SecretBlockError::Content)
        } else if secret == next_secret {
            Err(SecretBlockError::Seed)
        } else {
            Ok(SecretBlock {
                block_hash,
                seed: Seed::new(secret, next_secret),
                request: SigningRequest::new(
                    get_u64(buf, SEC_TIME_RANGE),
                    get_hash(buf, SEC_AUTH_HASH_RANGE),
                    get_hash(buf, SEC_STATE_HASH_RANGE),
                ),
                index: get_u64(buf, SEC_INDEX_RANGE),
                previous_hash: get_hash(buf, SEC_PREV_HASH_RANGE),
            })
        }
    }

    pub fn from_hash_at_index(buf: &[u8], block_hash: &Hash, index: u64) -> SecretBlockResult {
        let block = Self::open(buf)?;
        if block_hash != &block.block_hash {
            Err(SecretBlockError::Hash)
        } else if index != block.index {
            Err(SecretBlockError::Index)
        } else {
            Ok(block)
        }
    }

    pub fn from_previous(buf: &[u8], prev: &SecretBlock) -> SecretBlockResult {
        let block = Self::open(buf)?;
        if block.previous_hash != prev.block_hash {
            Err(SecretBlockError::PreviousHash)
        } else if block.seed.secret != prev.seed.next_secret {
            Err(SecretBlockError::SeedSequence)
        } else if block.index != prev.index + 1 {
            Err(SecretBlockError::Index)
        } else {
            Ok(block)
        }
    }
}

/// Builds a new [SecretBlock] up in a buffer.
#[derive(Debug)]
pub struct MutSecretBlock<'a> {
    buf: &'a mut [u8],
}

impl<'a> MutSecretBlock<'a> {
    pub fn new(buf: &'a mut [u8], seed: &Seed, request: &SigningRequest) -> Self {
        check_secretblock_buf(buf);
        buf.fill(0);

        set_hash(buf, SEC_SECRET_RANGE, &seed.secret);
        set_hash(buf, SEC_NEXT_SECRET_RANGE, &seed.next_secret);

        set_u64(buf, SEC_TIME_RANGE, request.time);
        set_hash(buf, SEC_AUTH_HASH_RANGE, &request.auth_hash);
        set_hash(buf, SEC_STATE_HASH_RANGE, &request.state_hash);

        Self { buf }
    }

    pub fn set_previous(&mut self, prev: &SecretBlock) {
        set_u64(self.buf, SEC_INDEX_RANGE, prev.index + 1);
        set_hash(self.buf, SEC_PREV_HASH_RANGE, &prev.block_hash);
    }

    fn finalize_hash(&mut self) -> Hash {
        let block_hash = hash(&self.buf[DIGEST..]);
        set_hash(self.buf, SEC_HASH_RANGE, &block_hash);
        block_hash
    }

    pub fn finalize(mut self) -> SecretBlock {
        let block_hash = self.finalize_hash();
        let index = get_u64(self.buf, SEC_INDEX_RANGE); // FIXME
        SecretBlock::from_hash_at_index(self.buf, &block_hash, index).unwrap()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::testhelpers::{BitFlipper, HashBitFlipper, random_request};

    fn valid_secret_block() -> [u8; SECRET_BLOCK] {
        let mut buf = [0; SECRET_BLOCK];
        set_hash(&mut buf, SEC_SECRET_RANGE, &Hash::from_bytes([1; DIGEST]));
        set_hash(
            &mut buf,
            SEC_NEXT_SECRET_RANGE,
            &Hash::from_bytes([2; DIGEST]),
        );
        set_hash(
            &mut buf,
            SEC_AUTH_HASH_RANGE,
            &Hash::from_bytes([3; DIGEST]),
        );
        set_hash(
            &mut buf,
            SEC_STATE_HASH_RANGE,
            &Hash::from_bytes([4; DIGEST]),
        );
        set_u64(&mut buf, SEC_INDEX_RANGE, 1);
        set_hash(
            &mut buf,
            SEC_PREV_HASH_RANGE,
            &Hash::from_bytes([5; DIGEST]),
        );
        let block_hash = hash(&buf[DIGEST..]);
        set_hash(&mut buf, SEC_HASH_RANGE, &block_hash);
        buf
    }

    #[test]
    fn test_check_secretblock_buf() {
        let buf = [0; SECRET_BLOCK];
        check_secretblock_buf(&buf);
        assert_eq!(buf, [0; SECRET_BLOCK]);
    }

    #[test]
    #[should_panic(expected = "Need a 208 byte slice; got 207 bytes")]
    fn test_check_secretblock_buf_panic_low() {
        let buf = [0; SECRET_BLOCK - 1];
        check_secretblock_buf(&buf);
    }

    #[test]
    #[should_panic(expected = "Need a 208 byte slice; got 209 bytes")]
    fn test_check_secretblock_buf_panic_high() {
        let buf = [0; SECRET_BLOCK + 1];
        check_secretblock_buf(&buf);
    }

    #[test]
    fn test_block_open() {
        let buf = valid_secret_block();
        let block = SecretBlock::open(&buf).unwrap();
        assert_eq!(
            block.block_hash,
            Hash::from_hex("c79720e9f45128d27bce83e91182267b6034702a0506d5d08e52681f12a0c6fc")
                .unwrap()
        );
        assert_eq!(block.seed.secret, Hash::from_bytes([1; DIGEST]));
        assert_eq!(block.seed.next_secret, Hash::from_bytes([2; DIGEST]));
        assert_eq!(block.request.auth_hash, Hash::from_bytes([3; DIGEST]));
        assert_eq!(block.request.state_hash, Hash::from_bytes([4; DIGEST]));
        assert_eq!(block.previous_hash, Hash::from_bytes([5; DIGEST]));
        for bad in BitFlipper::new(&buf) {
            assert_eq!(SecretBlock::open(&bad[..]), Err(SecretBlockError::Content));
        }

        let mut buf = valid_secret_block();
        for i in 0..=255 {
            let seed = Seed {
                secret: Hash::from_bytes([i; DIGEST]),
                next_secret: Hash::from_bytes([i; DIGEST]),
            };
            let request = random_request();
            let mut block = MutSecretBlock::new(&mut buf, &seed, &request);
            block.finalize_hash();
            assert_eq!(SecretBlock::open(&buf), Err(SecretBlockError::Seed));
        }
    }

    #[test]
    fn test_block_from_hash_at_index() {
        let buf = valid_secret_block();
        let block_hash = hash(&buf[DIGEST..]);
        SecretBlock::from_hash_at_index(&buf, &block_hash, 1).unwrap();

        // Test errors specific to SecretBlock::from_hash_at_index():
        for bad in HashBitFlipper::new(&block_hash) {
            assert_eq!(
                SecretBlock::from_hash_at_index(&buf, &bad, 1),
                Err(SecretBlockError::Hash)
            );
        }

        // Make sure SecretBlock::open() is getting called:
        for bad in BitFlipper::new(&buf) {
            assert_eq!(
                SecretBlock::from_hash_at_index(&bad[..], &block_hash, 1),
                Err(SecretBlockError::Content)
            );
        }
        let mut buf = valid_secret_block();
        for i in 0..=255 {
            let seed = Seed {
                secret: Hash::from_bytes([i; DIGEST]),
                next_secret: Hash::from_bytes([i; DIGEST]),
            };
            let request = random_request();
            let mut block = MutSecretBlock::new(&mut buf, &seed, &request);
            block.finalize_hash();
            assert_eq!(
                SecretBlock::from_hash_at_index(&buf, &block_hash, 1),
                Err(SecretBlockError::Seed)
            );
        }
    }

    #[test]
    fn test_block_from_previous() {
        let buf = valid_secret_block();
        let prev = SecretBlock {
            block_hash: get_hash(&buf, SEC_PREV_HASH_RANGE),
            seed: Seed::new(Hash::from_bytes([0; 32]), get_hash(&buf, SEC_SECRET_RANGE)),
            request: SigningRequest::new(0, Hash::from_bytes([0; 32]), Hash::from_bytes([0; 32])),
            index: 0,
            previous_hash: Hash::from_bytes([0; 32]),
        };
        SecretBlock::from_previous(&buf, &prev).unwrap();

        // Test errors specific to SecretBlock::from_previous():
        for bad_block_hash in HashBitFlipper::new(&prev.block_hash) {
            let bad_prev = SecretBlock {
                block_hash: bad_block_hash,
                seed: prev.seed,
                request: prev.request,
                index: 0,
                previous_hash: prev.previous_hash,
            };
            assert_eq!(
                SecretBlock::from_previous(&buf, &bad_prev),
                Err(SecretBlockError::PreviousHash)
            );
        }
        for bad_next_secret in HashBitFlipper::new(&prev.seed.next_secret) {
            let bad_prev = SecretBlock {
                block_hash: prev.block_hash,
                seed: Seed::new(prev.seed.secret, bad_next_secret),
                request: prev.request,
                index: 0,
                previous_hash: prev.previous_hash,
            };
            assert_eq!(
                SecretBlock::from_previous(&buf, &bad_prev),
                Err(SecretBlockError::SeedSequence)
            );
        }

        // Make sure SecretBlock::open() is getting called:
        for bad in BitFlipper::new(&buf) {
            assert_eq!(
                SecretBlock::from_previous(&bad[..], &prev),
                Err(SecretBlockError::Content)
            );
        }
        let mut buf = valid_secret_block();
        for i in 0..=255 {
            let seed = Seed {
                secret: Hash::from_bytes([i; DIGEST]),
                next_secret: Hash::from_bytes([i; DIGEST]),
            };
            let request = random_request();
            let mut block = MutSecretBlock::new(&mut buf, &seed, &request);
            block.finalize_hash();
            assert_eq!(
                SecretBlock::from_previous(&buf, &prev),
                Err(SecretBlockError::Seed)
            );
        }
    }

    #[test]
    fn test_mut_block_new() {
        let mut buf = [69; SECRET_BLOCK];
        let seed = Seed::create(&Hash::from_bytes([69; 32]));
        let request = SigningRequest::new(
            0,
            Hash::from_bytes([13; DIGEST]),
            Hash::from_bytes([42; DIGEST]),
        );
        MutSecretBlock::new(&mut buf, &seed, &request);
        assert_ne!(buf, [69; SECRET_BLOCK]);
        assert_eq!(
            buf,
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 9, 253, 30, 6, 249, 18, 171, 84, 19, 62, 24, 21, 201, 205, 86, 68, 150,
                57, 60, 28, 90, 199, 222, 217, 117, 98, 117, 95, 85, 68, 13, 139, 81, 71, 83, 252,
                176, 21, 151, 8, 29, 122, 107, 144, 241, 142, 43, 193, 43, 176, 152, 50, 175, 128,
                168, 219, 8, 72, 38, 149, 74, 180, 245, 26, 0, 0, 0, 0, 0, 0, 0, 0, 13, 13, 13, 13,
                13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
                13, 13, 13, 13, 13, 13, 13, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
                42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }
}
