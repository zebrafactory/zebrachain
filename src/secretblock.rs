//! Wire format for secret seeds when written to nonvolatile storage.

use crate::secretseed::Seed;
use crate::tunable::*;
use blake3::{hash, Hash};
use std::ops::Range;

const SECRET_INDEX: usize = 1;
const NEXT_SECRET_INDEX: usize = 2;
const STATE_INDEX: usize = 3;
const PREVIOUS_INDEX: usize = 4;

fn check_secret_buf(buf: &[u8]) {
    if buf.len() != SECRET_BLOCK {
        panic!("Need a {SECRET_BLOCK} byte slice; got {} bytes", buf.len());
    }
}

fn hash_range(index: usize) -> Range<usize> {
    index * DIGEST..(index + 1) * DIGEST
}

fn get_hash(buf: &[u8], index: usize) -> Hash {
    let range = hash_range(index);
    Hash::from_bytes(buf[range].try_into().unwrap())
}

fn set_hash(buf: &mut [u8], index: usize, value: &Hash) {
    let range = hash_range(index);
    buf[range].copy_from_slice(value.as_bytes());
}

#[derive(Debug, PartialEq)]
pub struct SecretBlock {
    pub block_hash: Hash,
    pub secret: Hash,
    pub next_secret: Hash,
    pub state_hash: Hash,
    pub previous_hash: Hash,
}

impl SecretBlock {
    pub fn get_seed(&self) -> Seed {
        Seed::new(self.secret, self.next_secret)
    }

    pub fn open(buf: &[u8]) -> SecretBlockResult {
        check_secret_buf(buf);
        let computed_hash = hash(&buf[DIGEST..]);
        let block = SecretBlock {
            block_hash: get_hash(buf, 0),
            secret: get_hash(buf, SECRET_INDEX),
            next_secret: get_hash(buf, NEXT_SECRET_INDEX),
            state_hash: get_hash(buf, STATE_INDEX),
            previous_hash: get_hash(buf, PREVIOUS_INDEX),
        };
        if computed_hash != block.block_hash {
            Err(SecretBlockError::Content)
        } else if block.secret == block.next_secret {
            Err(SecretBlockError::Seed)
        } else {
            Ok(block)
        }
    }

    pub fn from_hash(buf: &[u8], block_hash: &Hash) -> SecretBlockResult {
        let block = Self::open(buf)?;
        if block_hash != &block.block_hash {
            Err(SecretBlockError::Hash)
        } else {
            Ok(block)
        }
    }

    pub fn from_previous(buf: &[u8], prev: &SecretBlock) -> SecretBlockResult {
        let block = Self::open(buf)?;
        if block.previous_hash != prev.block_hash {
            Err(SecretBlockError::PreviousHash)
        } else if block.secret != prev.next_secret {
            Err(SecretBlockError::SeedSequence)
        } else {
            Ok(block)
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum SecretBlockError {
    Content,
    Seed,
    SeedSequence,
    Hash,
    PreviousHash,
}

pub type SecretBlockResult = Result<SecretBlock, SecretBlockError>;

#[derive(Debug)]
pub struct MutSecretBlock<'a> {
    buf: &'a mut [u8],
}

impl<'a> MutSecretBlock<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        check_secret_buf(buf);
        buf.fill(0);
        Self { buf }
    }

    pub fn set_seed(&mut self, seed: &Seed) {
        set_hash(self.buf, SECRET_INDEX, &seed.secret);
        set_hash(self.buf, NEXT_SECRET_INDEX, &seed.next_secret);
    }

    pub fn set_state_hash(&mut self, state_hash: &Hash) {
        set_hash(self.buf, STATE_INDEX, state_hash);
    }

    pub fn set_previous(&mut self, prev: &SecretBlock) {
        set_hash(self.buf, PREVIOUS_INDEX, &prev.block_hash)
    }

    fn finalize_hash(&mut self) -> Hash {
        let block_hash = hash(&self.buf[DIGEST..]);
        set_hash(self.buf, 0, &block_hash);
        block_hash
    }

    pub fn finalize(mut self) -> SecretBlock {
        let block_hash = self.finalize_hash();
        SecretBlock::from_hash(self.buf, &block_hash).unwrap()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::misc::{BitFlipper, HashBitFlipper};

    fn valid_secret_block() -> [u8; SECRET_BLOCK] {
        let mut buf = [0; SECRET_BLOCK];
        set_hash(&mut buf, SECRET_INDEX, &Hash::from_bytes([1; DIGEST]));
        set_hash(&mut buf, NEXT_SECRET_INDEX, &Hash::from_bytes([2; DIGEST]));
        set_hash(&mut buf, STATE_INDEX, &Hash::from_bytes([3; DIGEST]));
        set_hash(&mut buf, PREVIOUS_INDEX, &Hash::from_bytes([4; DIGEST]));
        let block_hash = hash(&buf[DIGEST..]);
        set_hash(&mut buf, 0, &block_hash);
        buf
    }

    #[test]
    fn test_check_secret_buf() {
        let buf = [0; SECRET_BLOCK];
        check_secret_buf(&buf);
        assert_eq!(buf, [0; SECRET_BLOCK]);
    }

    #[test]
    #[should_panic(expected = "Need a 160 byte slice; got 159 bytes")]
    fn test_check_secret_buf_panic_low() {
        let buf = [0; SECRET_BLOCK - 1];
        check_secret_buf(&buf);
    }

    #[test]
    #[should_panic(expected = "Need a 160 byte slice; got 161 bytes")]
    fn test_check_secret_buf_panic_high() {
        let buf = [0; SECRET_BLOCK + 1];
        check_secret_buf(&buf);
    }

    #[test]
    fn test_block_open() {
        let buf = valid_secret_block();
        let block = SecretBlock::open(&buf).unwrap();
        assert_eq!(
            block.block_hash,
            Hash::from_hex("cf003f3cff7ebdbc562c85b6735046a094ed68e2708b6a253d234ed2f273ede6")
                .unwrap()
        );
        assert_eq!(block.secret, Hash::from_bytes([1; DIGEST]));
        assert_eq!(block.next_secret, Hash::from_bytes([2; DIGEST]));
        assert_eq!(block.state_hash, Hash::from_bytes([3; DIGEST]));
        assert_eq!(block.previous_hash, Hash::from_bytes([4; DIGEST]));
        for bad in BitFlipper::new(&buf) {
            assert_eq!(SecretBlock::open(&bad[..]), Err(SecretBlockError::Content));
        }

        let mut buf = valid_secret_block();
        for i in 0..=255 {
            let mut block = MutSecretBlock::new(&mut buf);
            let seed = Seed {
                secret: Hash::from_bytes([i; DIGEST]),
                next_secret: Hash::from_bytes([i; DIGEST]),
            };
            block.set_seed(&seed);
            block.finalize_hash();
            assert_eq!(SecretBlock::open(&buf), Err(SecretBlockError::Seed));
        }
    }

    #[test]
    fn test_block_from_hash() {
        let buf = valid_secret_block();
        let block_hash = hash(&buf[DIGEST..]);
        let block = SecretBlock::from_hash(&buf, &block_hash).unwrap();

        // Test error specific to SecretBlock::from_hash():
        for bad in HashBitFlipper::new(&block_hash) {
            assert_eq!(
                SecretBlock::from_hash(&buf, &bad),
                Err(SecretBlockError::Hash)
            );
        }

        // Make sure SecretBlock::open() is getting called:
        for bad in BitFlipper::new(&buf) {
            assert_eq!(
                SecretBlock::from_hash(&bad[..], &block_hash),
                Err(SecretBlockError::Content)
            );
        }
        let mut buf = valid_secret_block();
        for i in 0..=255 {
            let mut block = MutSecretBlock::new(&mut buf);
            let seed = Seed {
                secret: Hash::from_bytes([i; DIGEST]),
                next_secret: Hash::from_bytes([i; DIGEST]),
            };
            block.set_seed(&seed);
            block.finalize_hash();
            assert_eq!(
                SecretBlock::from_hash(&buf, &block_hash),
                Err(SecretBlockError::Seed)
            );
        }
    }

    #[test]
    fn test_block_from_previous() {
        let buf = valid_secret_block();
        let prev = SecretBlock {
            block_hash: get_hash(&buf, PREVIOUS_INDEX),
            secret: Hash::from_bytes([0; 32]),
            next_secret: get_hash(&buf, SECRET_INDEX),
            state_hash: Hash::from_bytes([0; 32]),
            previous_hash: Hash::from_bytes([0; 32]),
        };
        let block = SecretBlock::from_previous(&buf, &prev).unwrap();

        // Test errors specific to SecretBlock::from_previous():
        for bad_block_hash in HashBitFlipper::new(&prev.block_hash) {
            let bad_prev = SecretBlock {
                block_hash: bad_block_hash,
                secret: prev.secret,
                next_secret: prev.next_secret,
                state_hash: prev.state_hash,
                previous_hash: prev.previous_hash,
            };
            assert_eq!(
                SecretBlock::from_previous(&buf, &bad_prev),
                Err(SecretBlockError::PreviousHash)
            );
        }
        for bad_next_secret in HashBitFlipper::new(&prev.next_secret) {
            let bad_prev = SecretBlock {
                block_hash: prev.block_hash,
                secret: prev.secret,
                next_secret: bad_next_secret,
                state_hash: prev.state_hash,
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
            let mut block = MutSecretBlock::new(&mut buf);
            let seed = Seed {
                secret: Hash::from_bytes([i; DIGEST]),
                next_secret: Hash::from_bytes([i; DIGEST]),
            };
            block.set_seed(&seed);
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
        let mut block = MutSecretBlock::new(&mut buf);
        assert_eq!(buf, [0; SECRET_BLOCK]);
    }

    #[test]
    fn test_mut_block_set_seed() {
        let seed = Seed::create(&[69; 32]);
        let mut buf = [0; SECRET_BLOCK];
        let mut block = MutSecretBlock::new(&mut buf);
        block.set_seed(&seed);
        assert_eq!(
            buf,
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 126, 181, 75, 23, 139, 24, 30, 103, 78, 67, 183, 50, 113, 40, 111, 123,
                177, 241, 207, 25, 212, 110, 114, 199, 42, 230, 214, 104, 228, 129, 178, 174, 175,
                79, 81, 160, 51, 80, 28, 213, 210, 42, 68, 97, 174, 58, 207, 124, 133, 195, 216,
                186, 106, 75, 254, 114, 141, 255, 123, 152, 135, 170, 146, 150, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0
            ]
        );
    }
}
