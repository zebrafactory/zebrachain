//! Wire format for secret seeds when written to nonvolatile storage.

use crate::always::*;
use crate::errors::SecretBlockError;
use crate::payload::Payload;
use crate::secretseed::Seed;
use blake3::{Hash, hash};

fn check_secretblock_buf(buf: &[u8]) {
    if buf.len() != SECRET_BLOCK {
        panic!("Need a {SECRET_BLOCK} byte slice; got {} bytes", buf.len());
    }
}

/// Alias for `Result<SecretBlock, SecretBlockError`.
pub type SecretBlockResult = Result<SecretBlock, SecretBlockError>;

/// Wire format for saving secret chain to nonvolatile storage.
#[derive(Debug, PartialEq, Clone)]
pub struct SecretBlock {
    pub block_hash: Hash,
    pub public_block_hash: Hash,
    pub seed: Seed,
    pub payload: Payload,
    pub index: u64,
    pub previous_hash: Hash,
}

impl SecretBlock {
    pub fn open(buf: &[u8]) -> SecretBlockResult {
        check_secretblock_buf(buf);
        let computed_hash = hash(&buf[DIGEST..]);
        let block_hash = get_hash(buf, SEC_HASH_RANGE);
        if computed_hash != block_hash {
            Err(SecretBlockError::Content)
        } else {
            Ok(SecretBlock {
                block_hash,
                public_block_hash: get_hash(buf, SEC_PUBLIC_HASH_RANGE),
                seed: Seed::from_buf(&buf[SEC_SEED_RANGE])?,
                payload: Payload::from_buf(&buf[SEC_PAYLOAD_RANGE]),
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

// FIXME
pub type SecretBlockState = SecretBlock;

/// Builds a new [SecretBlock] up in a buffer.
#[derive(Debug)]
pub struct MutSecretBlock<'a> {
    buf: &'a mut [u8],
}

impl<'a> MutSecretBlock<'a> {
    pub fn new(buf: &'a mut [u8], payload: &Payload) -> Self {
        check_secretblock_buf(buf);
        buf.fill(0);
        payload.write_to_buf(&mut buf[SEC_PAYLOAD_RANGE]);
        Self { buf }
    }

    pub fn set_previous(&mut self, prev: &SecretBlock) {
        set_u64(self.buf, SEC_INDEX_RANGE, prev.index + 1);
        set_hash(self.buf, SEC_PREV_HASH_RANGE, &prev.block_hash);
    }

    pub fn set_seed(&mut self, seed: &Seed) {
        seed.write_to_buf(&mut self.buf[SEC_SEED_RANGE]);
    }

    pub fn set_public_block_hash(&mut self, public_block_hash: &Hash) {
        set_hash(self.buf, SEC_PUBLIC_HASH_RANGE, public_block_hash);
    }

    pub fn finalize(self) -> Hash {
        let block_hash = hash(&self.buf[DIGEST..]);
        set_hash(self.buf, SEC_HASH_RANGE, &block_hash);
        block_hash
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::testhelpers::{BitFlipper, HashBitFlipper, random_hash, random_payload};

    fn valid_secret_block() -> [u8; SECRET_BLOCK] {
        let mut buf = [0; SECRET_BLOCK];
        set_hash(
            &mut buf,
            SEC_PUBLIC_HASH_RANGE,
            &Hash::from_bytes([7; DIGEST]),
        );
        let seed = Seed::new(Hash::from_bytes([1; DIGEST]), Hash::from_bytes([2; DIGEST]));
        seed.write_to_buf(&mut buf[SEC_SEED_RANGE]);
        let payload = Payload::new(314, Hash::from_bytes([3; DIGEST]));
        payload.write_to_buf(&mut buf[SEC_PAYLOAD_RANGE]);
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
            Hash::from_hex("3c244ad689b7bcefc05f77b8b385d58bdc356d7b0801de8774eaec7c5b0d2fd8")
                .unwrap()
        );
        assert_eq!(block.public_block_hash, Hash::from_bytes([7; DIGEST]));
        assert_eq!(block.seed.secret, Hash::from_bytes([1; DIGEST]));
        assert_eq!(block.seed.next_secret, Hash::from_bytes([2; DIGEST]));
        assert_eq!(block.payload.state_hash, Hash::from_bytes([3; DIGEST]));
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
            let payload = random_payload();
            let mut block = MutSecretBlock::new(&mut buf, &payload);
            block.set_seed(&seed);
            block.finalize();
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
            let payload = random_payload();
            let mut block = MutSecretBlock::new(&mut buf, &payload);
            block.set_seed(&seed);
            block.finalize();
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
            public_block_hash: get_hash(&buf, SEC_PUBLIC_HASH_RANGE),
            seed: Seed::new(
                Hash::from_bytes([0; 32]),
                get_hash(&buf[SEC_SEED_RANGE], 0..DIGEST),
            ),
            payload: Payload::new(0, Hash::from_bytes([0; 32])),
            index: 0,
            previous_hash: Hash::from_bytes([0; 32]),
        };
        SecretBlock::from_previous(&buf, &prev).unwrap();

        // Test errors specific to SecretBlock::from_previous():
        for bad_block_hash in HashBitFlipper::new(&prev.block_hash) {
            let bad_prev = SecretBlock {
                block_hash: bad_block_hash,
                public_block_hash: prev.public_block_hash,
                seed: prev.seed,
                payload: prev.payload,
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
                public_block_hash: prev.public_block_hash,
                seed: Seed::new(prev.seed.secret, bad_next_secret),
                payload: prev.payload,
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
            let payload = random_payload();
            let mut block = MutSecretBlock::new(&mut buf, &payload);
            block.set_seed(&seed);
            block.finalize();
            assert_eq!(
                SecretBlock::from_previous(&buf, &prev),
                Err(SecretBlockError::Seed)
            );
        }
    }

    #[test]
    fn test_mutblock_new() {
        let mut buf = [69; SECRET_BLOCK];
        let payload = Payload::new(1234567890, Hash::from_bytes([13; DIGEST]));
        MutSecretBlock::new(&mut buf, &payload);
        assert_ne!(buf, [69; SECRET_BLOCK]);
        assert_eq!(
            buf,
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 210, 2, 150, 73, 0, 0, 0, 0, 13,
                13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
                13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn test_mutblock_kat() {
        let mut buf = [0; SECRET_BLOCK];
        let payload = Payload::new(314, Hash::from_bytes([42; DIGEST]));
        let prev = SecretBlockState {
            block_hash: Hash::from_bytes([123; DIGEST]),
            public_block_hash: random_hash(),
            seed: Seed::auto_create().unwrap(),
            payload: random_payload(),
            index: 987,
            previous_hash: random_hash(),
        };
        let seed = Seed::create(&Hash::from_bytes([69; DIGEST]));
        let public_block_hash = Hash::from_bytes([42; DIGEST]);

        let mut block = MutSecretBlock::new(&mut buf, &payload);
        block.set_previous(&prev);
        block.set_seed(&seed);
        block.set_public_block_hash(&public_block_hash);
        let block_hash = block.finalize();
        assert_eq!(
            buf,
            [
                237, 26, 54, 206, 239, 59, 62, 215, 7, 77, 207, 123, 33, 224, 169, 136, 13, 162,
                74, 136, 232, 230, 31, 78, 111, 186, 123, 18, 236, 94, 136, 167, 42, 42, 42, 42,
                42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
                42, 42, 42, 42, 42, 42, 42, 9, 253, 30, 6, 249, 18, 171, 84, 19, 62, 24, 21, 201,
                205, 86, 68, 150, 57, 60, 28, 90, 199, 222, 217, 117, 98, 117, 95, 85, 68, 13, 139,
                81, 71, 83, 252, 176, 21, 151, 8, 29, 122, 107, 144, 241, 142, 43, 193, 43, 176,
                152, 50, 175, 128, 168, 219, 8, 72, 38, 149, 74, 180, 245, 26, 58, 1, 0, 0, 0, 0,
                0, 0, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
                42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 220, 3, 0, 0, 0, 0, 0, 0, 123,
                123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123,
                123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123
            ]
        );
        assert_eq!(&buf[0..DIGEST], block_hash.as_bytes());
    }

    #[test]
    fn test_mutblock_set_previous() {
        let mut buf = [0; SECRET_BLOCK];
        let payload = random_payload();
        let mut block = MutSecretBlock::new(&mut buf, &payload);
        assert_eq!(block.buf[SEC_INDEX_RANGE], [0; 8]);
        assert_eq!(block.buf[SEC_PREV_HASH_RANGE], [0; 32]);
        let prev = SecretBlock {
            block_hash: random_hash(),
            public_block_hash: random_hash(),
            seed: Seed::auto_create().unwrap(),
            payload: random_payload(),
            index: 69,
            previous_hash: random_hash(),
        };
        block.set_previous(&prev);
        assert_eq!(block.buf[SEC_INDEX_RANGE], [70, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&block.buf[SEC_PREV_HASH_RANGE], prev.block_hash.as_bytes());
    }

    #[test]
    fn test_mutblock_set_seed() {
        let mut buf = [0; SECRET_BLOCK];
        let payload = random_payload();
        let mut block = MutSecretBlock::new(&mut buf, &payload);
        let seed = Seed::auto_create().unwrap();
        assert_eq!(&block.buf[SEC_SEED_RANGE], &[0; DIGEST * 2]);
        block.set_seed(&seed);
        assert_ne!(&block.buf[SEC_SEED_RANGE], &[0; DIGEST * 2]);
        assert_eq!(
            &block.buf[SEC_SEED_RANGE][0..DIGEST],
            seed.secret.as_bytes()
        );
        assert_eq!(
            &block.buf[SEC_SEED_RANGE][DIGEST..DIGEST * 2],
            seed.next_secret.as_bytes()
        );
        let block_hash = block.finalize();
        let blockstate = SecretBlock::from_hash_at_index(&buf, &block_hash, 0).unwrap();
        assert_eq!(blockstate.block_hash, block_hash);
        assert_eq!(blockstate.payload, payload);
        assert_eq!(blockstate.seed, seed);
    }

    #[test]
    fn test_mutblock_set_public_block_hash() {
        let mut buf = [0; SECRET_BLOCK];
        let payload = random_payload();
        let mut block = MutSecretBlock::new(&mut buf, &payload);
        let seed = Seed::auto_create().unwrap();
        block.set_seed(&seed);
        assert_eq!(&block.buf[SEC_PUBLIC_HASH_RANGE], &[0; DIGEST]);
        let public_block_hash = random_hash();
        block.set_public_block_hash(&public_block_hash);
        assert_ne!(&block.buf[SEC_PUBLIC_HASH_RANGE], &[0; DIGEST]);
        assert_eq!(
            &block.buf[SEC_PUBLIC_HASH_RANGE],
            public_block_hash.as_bytes()
        );
        let block_hash = block.finalize();
        let blockstate = SecretBlock::from_hash_at_index(&buf, &block_hash, 0).unwrap();
        assert_eq!(blockstate.block_hash, block_hash);
        assert_eq!(blockstate.public_block_hash, public_block_hash);
        assert_eq!(blockstate.payload, payload);
        assert_eq!(blockstate.seed, seed);
    }

    #[test]
    fn test_mutblock_finalize() {
        let mut buf = [0; SECRET_BLOCK];
        let payload = random_payload();
        let block = MutSecretBlock::new(&mut buf, &payload);
        assert_eq!(block.buf[SEC_HASH_RANGE], [0; DIGEST]);
        let block_hash = block.finalize();
        assert_ne!(buf[SEC_HASH_RANGE], [0; DIGEST]);
        assert_eq!(&buf[SEC_HASH_RANGE], block_hash.as_bytes());
        assert_eq!(block_hash, hash(&buf[DIGEST..]));
    }
}
