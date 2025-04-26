//! Wire format for secret seeds when written to nonvolatile storage.

use crate::always::*;
use crate::errors::SecretBlockError;
use crate::payload::Payload;
use crate::secretseed::{Secret, Seed, derive_secret};
use blake3::{Hash, hash};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

fn check_secretblock_buf(buf: &[u8]) {
    if buf.len() != SECRET_BLOCK {
        panic!("Need a {SECRET_BLOCK} byte slice; got {} bytes", buf.len());
    }
}

// Split out of derive_block_key_and_nonce() for testability
#[inline]
fn derive_block_sub_secrets(block_secret: Secret) -> (Secret, Secret) {
    let key = derive_secret(CONTEXT_STORE_KEY, &block_secret);
    let nonce = derive_secret(CONTEXT_STORE_NONCE, &block_secret);
    (key, nonce)
}

// A unique key and nonce derived from the block secret.
fn get_block_key_and_nonce(block_secret: Secret) -> (Key, Nonce) {
    let (key, nonce) = derive_block_sub_secrets(block_secret);
    assert_ne!(key, nonce);
    let key = Key::from_slice(&key.as_bytes()[..]);
    let nonce = Nonce::from_slice(&nonce.as_bytes()[0..12]);
    (*key, *nonce)
}

fn encrypt_in_place(buf: &mut Vec<u8>, block_secret: Secret) {
    // FIXME: probably use &index.to_le_bytes() as additional data
    assert_eq!(buf.len(), SECRET_BLOCK);
    let (key, nonce) = get_block_key_and_nonce(block_secret);
    let cipher = ChaCha20Poly1305::new(&key);
    cipher.encrypt_in_place(&nonce, b"", buf).unwrap(); // This should not fail
    assert_eq!(buf.len(), SECRET_BLOCK_AEAD);
}

fn decrypt_in_place(buf: &mut Vec<u8>, block_secret: Secret) -> Result<(), SecretBlockError> {
    // FIXME: probably use &index.to_le_bytes() as additional data
    assert_eq!(buf.len(), SECRET_BLOCK_AEAD);
    let (key, nonce) = get_block_key_and_nonce(block_secret);
    let cipher = ChaCha20Poly1305::new(&key);
    if cipher.decrypt_in_place(&nonce, b"", buf).is_err() {
        Err(SecretBlockError::Storage)
    } else {
        assert_eq!(buf.len(), SECRET_BLOCK);
        Ok(())
    }
}

/// State needed to validate next secret block.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct SecretBlockState {
    /// Hash of this secret block.
    pub block_hash: Hash,

    /// Hash of corresponding public block.
    pub public_block_hash: Hash,

    /// Seed use to sign this block position.
    pub seed: Seed,

    /// Payload to be signed.
    pub payload: Payload,

    /// Block index.
    pub index: u64,

    /// Hash of previous secret block.
    pub previous_hash: Hash,
}

impl SecretBlockState {
    fn from_buf(buf: &[u8]) -> Result<Self, SecretBlockError> {
        check_secretblock_buf(buf);
        let computed_hash = hash(&buf[DIGEST..]);
        let block_hash = get_hash(buf, SEC_HASH_RANGE);
        if computed_hash != block_hash {
            Err(SecretBlockError::Content)
        } else {
            Ok(Self {
                block_hash,
                public_block_hash: get_hash(buf, SEC_PUBLIC_HASH_RANGE),
                seed: Seed::from_buf(&buf[SEC_SEED_RANGE])?,
                payload: Payload::from_buf(&buf[SEC_PAYLOAD_RANGE]),
                index: get_u64(buf, SEC_INDEX_RANGE),
                previous_hash: get_hash(buf, SEC_PREV_HASH_RANGE),
            })
        }
    }
}

/// Alias for `Result<SecretBlock, SecretBlockError>`.
pub type SecretBlockResult<'a> = Result<SecretBlock<'a>, SecretBlockError>;

/// Decrypts and validates a secret block.
pub struct SecretBlock<'a> {
    buf: &'a mut Vec<u8>,
}

impl<'a> SecretBlock<'a> {
    /// Create a new secret block wrapper but perform no validation.
    pub fn new(buf: &'a mut Vec<u8>) -> Self {
        Self { buf }
    }

    /// FIXME
    pub fn as_mut_read_buf(&mut self) -> &mut [u8] {
        self.buf.resize(SECRET_BLOCK_AEAD, 0);
        &mut self.buf
    }

    /// FIXME
    pub fn from_index(
        self,
        block_secret: Secret,
        index: u64,
    ) -> Result<SecretBlockState, SecretBlockError> {
        decrypt_in_place(self.buf, block_secret)?;
        let state = SecretBlockState::from_buf(&self.buf[0..SECRET_BLOCK])?;
        if index != state.index {
            Err(SecretBlockError::Index)
        } else {
            Ok(state)
        }
    }

    /// FIXME
    pub fn from_hash_at_index(
        self,
        block_secret: Secret,
        block_hash: &Hash,
        index: u64,
    ) -> Result<SecretBlockState, SecretBlockError> {
        let state = self.from_index(block_secret, index)?;
        if &state.block_hash != block_hash {
            Err(SecretBlockError::Hash)
        } else {
            Ok(state)
        }
    }

    /// FIXME
    pub fn from_previous(
        self,
        block_secret: Secret,
        prev: &SecretBlockState,
    ) -> Result<SecretBlockState, SecretBlockError> {
        let state = self.from_index(block_secret, prev.index + 1)?;
        if state.previous_hash != prev.block_hash {
            Err(SecretBlockError::PreviousHash)
        } else if state.seed.secret != prev.seed.next_secret {
            Err(SecretBlockError::SeedSequence)
        } else {
            Ok(state)
        }
    }
}

impl<'a> Drop for SecretBlock<'a> {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl<'a> ZeroizeOnDrop for SecretBlock<'a> {}

/// Builds a new [SecretBlock] up in a buffer.
#[derive(Debug)]
pub struct MutSecretBlock<'a> {
    buf: &'a mut Vec<u8>,
}

impl<'a> MutSecretBlock<'a> {
    /// Zero secret block buffer and set payload.
    pub fn new(buf: &'a mut Vec<u8>, payload: &Payload) -> Self {
        //check_secretblock_buf(buf);
        buf.resize(SECRET_BLOCK, 0);
        buf.fill(0);
        payload.write_to_buf(&mut buf[SEC_PAYLOAD_RANGE]);
        Self { buf }
    }

    /// Set needed secret block fields for block after `prev`.
    pub fn set_previous(&mut self, prev: &SecretBlockState) {
        set_u64(&mut self.buf, SEC_INDEX_RANGE, prev.index + 1);
        set_hash(&mut self.buf, SEC_PREV_HASH_RANGE, &prev.block_hash);
    }

    /// Write seed to buffer.
    pub fn set_seed(&mut self, seed: &Seed) {
        seed.write_to_buf(&mut self.buf[SEC_SEED_RANGE]);
    }

    /// Set hash of resulting public block (used for integrity check).
    pub fn set_public_block_hash(&mut self, public_block_hash: &Hash) {
        set_hash(&mut self.buf, SEC_PUBLIC_HASH_RANGE, public_block_hash);
    }

    /// Set and return block hash.
    pub fn finalize(mut self, block_secret: Secret) -> Hash {
        let block_hash = hash(&self.buf[DIGEST..]);
        set_hash(&mut self.buf, SEC_HASH_RANGE, &block_hash);
        encrypt_in_place(self.buf, block_secret);
        block_hash
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::secretseed::generate_secret;
    use crate::testhelpers::{BitFlipper, HashBitFlipper, random_hash, random_payload};
    use getrandom;
    use std::collections::HashSet;

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
    fn test_derive_block_sub_secrets_inner() {
        let count: usize = 420;
        let mut hset = HashSet::new();
        for _ in 0..count {
            let secret = generate_secret().unwrap();
            assert!(hset.insert(secret));
            let (key, nonce) = derive_block_sub_secrets(secret);
            assert!(hset.insert(key));
            assert!(hset.insert(nonce));
        }
        assert_eq!(hset.len(), 3 * count);
    }

    #[test]
    fn test_chacha20poly1305_roundtrip() {
        let mut buf = vec![0; SECRET_BLOCK];
        getrandom::fill(&mut buf).unwrap();
        let h = hash(&buf);
        let secret = generate_secret().unwrap();
        for index in 0..420 {
            encrypt_in_place(&mut buf, secret.clone());
            assert_eq!(buf.len(), SECRET_BLOCK_AEAD);
            assert_ne!(hash(&buf[0..SECRET_BLOCK]), h);
            decrypt_in_place(&mut buf, secret.clone()).unwrap();
            assert_eq!(hash(&buf[0..SECRET_BLOCK]), h);
            assert_eq!(hash(&buf), h);
        }
    }

    #[test]
    fn test_chacha20poly1305_error() {
        let mut buf = vec![0; SECRET_BLOCK];
        getrandom::fill(&mut buf).unwrap();
        let h = hash(&buf);
        let secret = generate_secret().unwrap();
        encrypt_in_place(&mut buf, secret.clone());
        for mut bad in BitFlipper::new(&buf) {
            assert!(decrypt_in_place(&mut bad, secret.clone()).is_err());
        }
        decrypt_in_place(&mut buf, secret.clone()).unwrap();
        assert_eq!(hash(&buf), h);
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
    fn test_secretblock_zeroize() {
        let mut buf = vec![69; SECRET_BLOCK_AEAD];
        {
            let block = SecretBlock::new(&mut buf);
            assert_eq!(block.buf, &vec![69; SECRET_BLOCK_AEAD]);
        }
        assert_eq!(buf, vec![]);
    }

    /*

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
    */

    #[test]
    fn test_mutblock_new() {
        let mut buf = vec![69; SECRET_BLOCK];
        let payload = Payload::new(1234567890, Hash::from_bytes([13; DIGEST]));
        MutSecretBlock::new(&mut buf, &payload);
        assert_ne!(buf, [69; SECRET_BLOCK]);
        assert_eq!(
            buf,
            vec![
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
    fn test_mutblock_set_previous() {
        let mut buf = vec![0; SECRET_BLOCK];
        let payload = random_payload();
        let mut block = MutSecretBlock::new(&mut buf, &payload);
        assert_eq!(block.buf[SEC_INDEX_RANGE], [0; 8]);
        assert_eq!(block.buf[SEC_PREV_HASH_RANGE], [0; 32]);
        let prev = SecretBlockState {
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
        let mut buf = vec![0; SECRET_BLOCK];
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
        let block_secret = generate_secret().unwrap();
        let block_hash = block.finalize(block_secret);
        let blockstate = SecretBlock::new(&mut buf)
            .from_hash_at_index(block_secret, &block_hash, 0)
            .unwrap();
        assert_eq!(blockstate.block_hash, block_hash);
        assert_eq!(blockstate.payload, payload);
        assert_eq!(blockstate.seed, seed);
    }

    #[test]
    fn test_mutblock_set_public_block_hash() {
        let mut buf = vec![0; SECRET_BLOCK];
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
        let block_secret = generate_secret().unwrap();
        let block_hash = block.finalize(block_secret);
        let blockstate = SecretBlock::new(&mut buf)
            .from_hash_at_index(block_secret, &block_hash, 0)
            .unwrap();
        assert_eq!(blockstate.block_hash, block_hash);
        assert_eq!(blockstate.public_block_hash, public_block_hash);
        assert_eq!(blockstate.payload, payload);
        assert_eq!(blockstate.seed, seed);
    }
}
