//! Block construction, validation, and wire format.

use crate::always::*;
use crate::errors::BlockError;
use crate::payload::Payload;
use crate::pksign::{SecretSigner, verify_block_signature};
use crate::secretseed::Seed;
use blake3::{Hash, hash};

fn check_block_buf(buf: &[u8]) {
    if buf.len() != BLOCK {
        panic!("Need a {BLOCK} byte slice; got {} bytes", buf.len());
    }
}

/// Contains state from current block needed to validate next block, plus the payload.
#[derive(Clone, Debug, PartialEq)]
pub struct BlockState {
    /// Block-wise position in chain, starting from zero.
    pub index: u64,

    /// Hash of this block.
    pub block_hash: Hash,

    /// Hash of first block in chain.
    pub chain_hash: Hash,

    /// Hash of previous block.
    pub previous_hash: Hash,

    /// Hash of the public key that will be used when signing the next block.
    pub next_pubkey_hash: Hash,

    /// The signed content.
    pub payload: Payload,
}

impl BlockState {
    /// Construct a new [BlockState].
    pub fn new(
        index: u64,
        block_hash: Hash,
        chain_hash: Hash,
        previous_hash: Hash,
        next_pubkey_hash: Hash,
        payload: Payload,
    ) -> Self {
        Self {
            index,
            block_hash,
            chain_hash,
            previous_hash,
            next_pubkey_hash,
            payload,
        }
    }

    /// Returns the [BlockState.block_hash] if index == 0, otherwise [BlockState.chain_hash].
    pub fn effective_chain_hash(&self) -> Hash {
        if self.index == 0 {
            self.block_hash
        } else {
            self.chain_hash
        }
    }

    // Warning: this does ZERO validation!
    fn from_buf(buf: &[u8]) -> Self {
        Self {
            index: get_u64(buf, INDEX_RANGE),
            block_hash: get_hash(buf, HASH_RANGE),
            chain_hash: get_hash(buf, CHAIN_HASH_RANGE),
            previous_hash: get_hash(buf, PREVIOUS_HASH_RANGE),
            next_pubkey_hash: get_hash(buf, NEXT_PUBKEY_HASH_RANGE),
            payload: Payload::from_buf(&buf[PAYLOAD_RANGE]),
        }
    }
}

/// Validate block wire format, extract items from the same.
#[derive(Debug, PartialEq)]
pub struct Block<'a> {
    buf: &'a [u8],
}

impl<'a> Block<'a> {
    /// Create a new block wrapper around `buf`, but perform no validation.
    pub fn new(buf: &'a [u8]) -> Self {
        check_block_buf(buf);
        Self { buf }
    }

    // Warning: This only performs internal validation on the block!
    // It does not validate relative to the chain!
    fn open(&self) -> Result<BlockState, BlockError> {
        let state = BlockState::from_buf(self.buf);
        if self.compute_hash() != state.block_hash {
            Err(BlockError::Content)
        } else if !self.signature_is_valid() {
            Err(BlockError::Signature)
        //} else if !self.first_block_is_valid() {
        //    Err(BlockError::FirstBlock)
        } else {
            Ok(state)
        }
    }

    /// Open and verify a block with `block_hash` at position `index` in the chain.
    ///
    /// This is used when loading the first block (`index=0`), or when resuming from a
    /// [CheckPoint][crate::chain::CheckPoint].
    pub fn from_hash_at_index(
        &self,
        block_hash: &Hash,
        index: u64,
    ) -> Result<BlockState, BlockError> {
        let state = self.open()?;
        if block_hash != &state.block_hash {
            Err(BlockError::Hash)
        } else if index != state.index {
            Err(BlockError::Index)
        } else {
            Ok(state)
        }
    }

    /// Open and verify the block that comes after the previous [BlockState] `prev`.
    ///
    /// This is done when walking the chain for verification (blocks after the first block, or,
    /// when resuming from a checkpoint, blocks after that checkpoint block).
    pub fn from_previous(&self, prev: &BlockState) -> Result<BlockState, BlockError> {
        let state = self.open()?;
        if self.compute_pubkey_hash() != prev.next_pubkey_hash {
            Err(BlockError::PubKeyHash)
        } else if state.index != prev.index + 1 {
            Err(BlockError::Index)
        } else if state.previous_hash != prev.block_hash {
            Err(BlockError::PreviousHash)
        } else if state.chain_hash != prev.effective_chain_hash() {
            Err(BlockError::ChainHash)
        } else {
            Ok(state)
        }
    }

    fn as_hashable(&self) -> &[u8] {
        &self.buf[HASHABLE_RANGE]
    }

    /// Bytes over which the ed25519 signature is computed.
    pub(crate) fn as_signable(&self) -> &[u8] {
        &self.buf[SIGNABLE_RANGE]
    }

    /// Bytes over which the ml-dsa signature is computed (includes ed25519 signature).
    pub(crate) fn as_signable2(&self) -> &[u8] {
        &self.buf[SIGNABLE2_RANGE]
    }

    /// The signature bytes (both ed25519 and ml-dsa signatures).
    pub(crate) fn as_signature(&self) -> &[u8] {
        &self.buf[SIGNATURE_RANGE]
    }

    /// The public key bytes (both ed25519 and ml-dsa public keys).
    pub(crate) fn as_pubkey(&self) -> &[u8] {
        &self.buf[PUBKEY_RANGE]
    }

    fn compute_hash(&self) -> Hash {
        hash(self.as_hashable())
    }

    fn compute_pubkey_hash(&self) -> Hash {
        hash(self.as_pubkey())
    }

    fn signature_is_valid(&self) -> bool {
        verify_block_signature(self)
    }
}

/// Builds of a new block in a buffer.
pub struct MutBlock<'a> {
    buf: &'a mut [u8],
}

impl<'a> MutBlock<'a> {
    /// Zero `buf` and set `payload`.
    pub fn new(buf: &'a mut [u8], payload: &Payload) -> Self {
        check_block_buf(buf);
        buf.fill(0);
        payload.write_to_buf(&mut buf[PAYLOAD_RANGE]);
        Self { buf }
    }

    /// Set index, chain_hash, and prev_hash based on [BlockState] `prev`.
    pub fn set_previous(&mut self, prev: &BlockState) {
        set_u64(self.buf, INDEX_RANGE, prev.index + 1);
        set_hash(self.buf, PREVIOUS_HASH_RANGE, &prev.block_hash);
        let chain_hash = prev.effective_chain_hash(); // Don't use prev.chain_hash !
        set_hash(self.buf, CHAIN_HASH_RANGE, &chain_hash);
    }

    /// Set hash of the public key that will be used for siging the next block.
    pub fn set_next_pubkey_hash(&mut self, next_pubkey_hash: &Hash) {
        set_hash(self.buf, NEXT_PUBKEY_HASH_RANGE, next_pubkey_hash);
    }

    /// Sign block using seed.
    pub fn sign(&mut self, seed: &Seed) {
        let signer = SecretSigner::new(seed);
        signer.sign(self);
    }

    /// Finalize the block (sets and returns block hash).
    pub fn finalize(self) -> Hash {
        let block_hash = hash(self.as_hashable());
        set_hash(self.buf, HASH_RANGE, &block_hash);
        block_hash
    }

    /// Bytes over which the block hash is computed.
    fn as_hashable(&self) -> &[u8] {
        &self.buf[HASHABLE_RANGE]
    }

    /// Signature as mutable bytes.
    pub(crate) fn as_mut_signature(&mut self) -> &mut [u8] {
        &mut self.buf[SIGNATURE_RANGE]
    }

    /// Public Key as mutable bytes.
    pub(crate) fn as_mut_pubkey(&mut self) -> &mut [u8] {
        &mut self.buf[PUBKEY_RANGE]
    }

    /// Bytes over which the ed25519 signature is made.
    pub(crate) fn as_signable(&self) -> &[u8] {
        &self.buf[SIGNABLE_RANGE]
    }

    /// Bytes over which the ml-dsa signature is made (includes ed25519 signature).
    pub(crate) fn as_signable2(&self) -> &[u8] {
        &self.buf[SIGNABLE2_RANGE]
    }

    /// Return hash of public key bytes.
    pub(crate) fn compute_pubkey_hash(&self) -> Hash {
        hash(&self.buf[PUBKEY_RANGE])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pksign::{SecretSigner, sign_block};
    use crate::secretseed::Seed;
    use crate::testhelpers::{
        BitFlipper, HashBitFlipper, U64BitFlipper, random_hash, random_payload,
    };
    use getrandom;

    const HEX0: &str = "fce9a075fcd4a1a5e867c491860dd6fe422f3747f3ccd3f4f927a1b51193f9a2";
    const HEX1: &str = "73f229cc4e11354b11cb17bb718fe9cc9c07192fa05bf09adcc05270a5843d7b";

    #[test]
    fn test_blockstate_effective_chain_hash() {
        let h1 = random_hash();
        let h2 = random_hash();
        let h3 = random_hash();
        let h4 = random_hash();
        let payload = random_payload();
        let bs = BlockState::new(0, h1, h2, h3, h4, payload);
        assert_eq!(bs.effective_chain_hash(), h1);
        let bs = BlockState::new(1, h1, h2, h3, h4, payload);
        assert_eq!(bs.effective_chain_hash(), h2);
    }

    #[test]
    fn test_blockstate_from_buf() {
        let mut buf = [0; BLOCK];
        getrandom::fill(&mut buf).unwrap();
        buf[HASH_RANGE].copy_from_slice(&[1; DIGEST]);
        buf[NEXT_PUBKEY_HASH_RANGE].copy_from_slice(&[2; DIGEST]);
        buf[PAYLOAD_RANGE].copy_from_slice(&[3; PAYLOAD]);
        buf[INDEX_RANGE].copy_from_slice(&[4; INDEX]);
        buf[CHAIN_HASH_RANGE].copy_from_slice(&[5; DIGEST]);
        buf[PREVIOUS_HASH_RANGE].copy_from_slice(&[6; DIGEST]);

        let expected = BlockState {
            index: 289360691352306692,
            block_hash: Hash::from_bytes([1; DIGEST]),
            chain_hash: Hash::from_bytes([5; DIGEST]),
            previous_hash: Hash::from_bytes([6; DIGEST]),
            next_pubkey_hash: Hash::from_bytes([2; DIGEST]),
            payload: Payload::new(
                4003321963775746628980877734491390723,
                Hash::from_bytes([3; DIGEST]),
            ),
        };
        assert_eq!(BlockState::from_buf(&buf), expected);
    }

    fn new_expected() -> Hash {
        Hash::from_hex(HEX0).unwrap()
    }

    fn new_valid_block() -> Vec<u8> {
        let mut buf = vec![0; BLOCK];
        let seed = Seed::create(&Hash::from_bytes([69; 32]));
        let secsign = SecretSigner::new(&seed);
        let payload = Payload::new(0, Hash::from_bytes([1; 32]));
        let mut block = MutBlock::new(&mut buf, &payload);
        let last = BlockState::new(
            0,
            Hash::from_bytes([3; 32]),
            ZERO_HASH,
            ZERO_HASH,
            Hash::from_bytes([5; 32]),
            payload,
        );
        block.set_previous(&last);
        secsign.sign(&mut block);
        block.finalize();
        buf
    }

    fn new_dummy_block() -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::with_capacity(BLOCK);
        buf.extend_from_slice(&[1; DIGEST]);
        buf.extend_from_slice(&[2; SIGNATURE]);
        buf.extend_from_slice(&[3; PUBKEY]);
        buf.extend_from_slice(&[4; DIGEST]); // NEXT_PUBKEY_HASH

        // Payload
        buf.extend_from_slice(&[5; TIME]); // TIME
        buf.extend_from_slice(&[7; DIGEST]); // STATE_HASH

        buf.extend_from_slice(&[8; INDEX]); // INDEX
        buf.extend_from_slice(&[10; DIGEST]); // CHAIN_HASH
        buf.extend_from_slice(&[9; DIGEST]); // PREVIOUS_HASH
        buf
    }

    #[test]
    fn test_block_new() {
        let buf: Vec<u8> = vec![69; BLOCK];
        let block = Block::new(&buf);
        assert_eq!(block.buf, vec![69; BLOCK]);
    }

    #[test]
    #[should_panic(expected = "Need a 5541 byte slice; got 5540 bytes")]
    fn test_block_new_short_panic() {
        let buf: Vec<u8> = vec![0; BLOCK - 1];
        let _block = Block::new(&buf);
    }

    #[test]
    #[should_panic(expected = "Need a 5541 byte slice; got 5542 bytes")]
    fn test_block_new_long_panic() {
        let buf: Vec<u8> = vec![0; BLOCK + 1];
        let _block = Block::new(&buf);
    }

    #[test]
    fn test_block_open() {
        let buf = new_valid_block();
        assert!(Block::new(&buf).open().is_ok());
        for bad in BitFlipper::new(&buf) {
            assert_eq!(Block::new(&bad).open(), Err(BlockError::Content));
        }
        let mut bad = vec![0; BLOCK];
        for end in BitFlipper::new(&buf[HASHABLE_RANGE]) {
            let h = hash(&end);
            bad[HASH_RANGE].copy_from_slice(h.as_bytes());
            bad[HASHABLE_RANGE].copy_from_slice(&end);
            assert_eq!(Block::new(&bad).open(), Err(BlockError::Signature));
        }
    }

    #[test]
    fn test_block_from_hash_at_index() {
        let buf = new_valid_block();
        let good = Block::new(&buf).open().unwrap().block_hash;
        assert!(Block::new(&buf).from_hash_at_index(&good, 1).is_ok());

        // Make sure Block::open() is getting called
        for bad in BitFlipper::new(&buf) {
            assert_eq!(
                Block::new(&bad).from_hash_at_index(&good, 0),
                Err(BlockError::Content)
            );
        }
        for badend in BitFlipper::new(&buf[DIGEST..]) {
            let mut badbuf = [0; BLOCK];
            badbuf[0..DIGEST].copy_from_slice(hash(&badend).as_bytes());
            badbuf[DIGEST..].copy_from_slice(&badend);
            assert_eq!(
                Block::new(&badbuf).from_hash_at_index(&good, 0),
                Err(BlockError::Signature)
            );
        }

        // Block::from_hash_at_index() specific error
        for bad in HashBitFlipper::new(&good) {
            assert_eq!(
                Block::new(&buf).from_hash_at_index(&bad, 0),
                Err(BlockError::Hash)
            );
        }
    }

    #[test]
    fn test_block_from_previous() {
        let buf = new_valid_block();
        let block = Block::new(&buf);
        let pubkey_hash = block.compute_pubkey_hash();
        let state = block.open().unwrap();

        // Cannot append from the current block
        assert!(Block::new(&buf).from_previous(&state).is_err());

        let prev = BlockState::new(
            // Previous block state
            0,
            state.previous_hash,
            ZERO_HASH,
            ZERO_HASH,
            pubkey_hash,
            state.payload,
        );
        assert!(Block::new(&buf).from_previous(&prev).is_ok());

        // Make sure Block::open() is getting called
        for bad in BitFlipper::new(&buf) {
            assert_eq!(
                Block::new(&bad).from_previous(&prev),
                Err(BlockError::Content)
            );
        }
        for badend in BitFlipper::new(&buf[DIGEST..]) {
            let mut badbuf = [0; BLOCK];
            badbuf[0..DIGEST].copy_from_slice(hash(&badend).as_bytes());
            badbuf[DIGEST..].copy_from_slice(&badend);
            assert_eq!(
                Block::new(&badbuf).from_previous(&prev),
                Err(BlockError::Signature)
            );
        }

        // Block::from_previous() specific errors
        for bad_next_pubkey_hash in HashBitFlipper::new(&prev.next_pubkey_hash) {
            let bad_prev = BlockState::new(
                0,
                prev.block_hash,
                prev.chain_hash,
                prev.previous_hash,
                bad_next_pubkey_hash,
                prev.payload,
            );
            assert_eq!(
                Block::new(&buf).from_previous(&bad_prev),
                Err(BlockError::PubKeyHash)
            );
        }
        for bad_block_hash in HashBitFlipper::new(&prev.block_hash) {
            let bad_prev = BlockState::new(
                0,
                bad_block_hash,
                prev.chain_hash,
                prev.previous_hash,
                prev.next_pubkey_hash,
                prev.payload,
            );
            assert_eq!(
                Block::new(&buf).from_previous(&bad_prev),
                Err(BlockError::PreviousHash)
            );
        }
        for bad_chain_hash in HashBitFlipper::new(&prev.chain_hash) {
            let bad_prev = BlockState::new(
                0,
                prev.block_hash,
                bad_chain_hash,
                prev.previous_hash,
                prev.next_pubkey_hash,
                prev.payload,
            );
            // Previous `BlockState.chain_hash` only gets checked in 3rd block and beyond:
            assert!(Block::new(&buf).from_previous(&bad_prev).is_ok());
        }
        for bad_index in U64BitFlipper::new(0) {
            let bad_prev = BlockState::new(
                bad_index,
                prev.block_hash,
                prev.chain_hash,
                prev.previous_hash,
                prev.next_pubkey_hash,
                prev.payload,
            );
            assert_eq!(
                Block::new(&buf).from_previous(&bad_prev),
                Err(BlockError::Index)
            );
        }
    }

    #[test]
    fn test_block_from_previous_3rd() {
        let mut buf = [0; BLOCK];
        let seed = Seed::auto_create().unwrap();
        let chain_hash = sign_block(&mut buf, &seed, &random_payload(), None);
        let tail = Block::new(&buf).from_hash_at_index(&chain_hash, 0).unwrap();

        let seed = seed.auto_advance().unwrap();
        sign_block(&mut buf, &seed, &random_payload(), Some(&tail));
        for bad_chain_hash in HashBitFlipper::new(&chain_hash) {
            let bad_prev = BlockState::new(
                0,
                tail.block_hash,
                bad_chain_hash,
                tail.previous_hash,
                tail.next_pubkey_hash,
                tail.payload,
            );
            // Previous `BlockState.chain_hash` only gets checked in 3rd block and beyond:
            assert!(Block::new(&buf).from_previous(&bad_prev).is_ok());
        }
        let tail = Block::new(&buf).from_previous(&tail).unwrap();

        // Sign 3rd block
        let seed = seed.auto_advance().unwrap();
        sign_block(&mut buf, &seed, &random_payload(), Some(&tail));
        assert!(Block::new(&buf).from_previous(&tail).is_ok());
        for bad_chain_hash in HashBitFlipper::new(&chain_hash) {
            let bad_prev = BlockState::new(
                1,
                tail.block_hash,
                bad_chain_hash,
                tail.previous_hash,
                tail.next_pubkey_hash,
                tail.payload,
            );
            assert_eq!(
                Block::new(&buf).from_previous(&bad_prev),
                Err(BlockError::ChainHash)
            );
        }
    }

    #[test]
    fn test_block_as_fns() {
        let buf = new_dummy_block();
        let block = Block::new(&buf);
        assert_eq!(block.as_signature(), [2; SIGNATURE]);
        assert_eq!(block.as_pubkey(), [3; PUBKEY]);
    }

    #[test]
    fn test_block_as_hashable() {
        let buf = new_dummy_block();
        let block = Block::new(&buf);
        assert_eq!(block.as_hashable(), &buf[DIGEST..]);
    }

    #[test]
    fn block_as_signable() {
        let buf = new_dummy_block();
        let block = Block::new(&buf);
        assert_eq!(block.as_signable(), &buf[DIGEST + SIGNATURE..]);
    }

    #[test]
    fn test_block_compute_hash() {
        let buf = new_dummy_block();
        let block = Block::new(&buf);
        let hash = block.compute_hash();
        assert_eq!(hash, new_expected());
    }

    #[test]
    fn test_block_signature_is_valid() {
        let good = new_valid_block();
        let block = Block::new(&good);
        assert!(block.signature_is_valid());
        for bad in BitFlipper::new(&good) {
            let block = Block::new(&bad);
            if bad[HASH_RANGE] == good[HASH_RANGE] {
                assert!(!block.signature_is_valid());
            } else {
                assert!(block.signature_is_valid());
            }
        }
    }

    #[test]
    fn test_mutblock_new() {
        let mut buf = [27; BLOCK];
        let payload = Payload::new(0, Hash::from_bytes([42; DIGEST]));
        MutBlock::new(&mut buf, &payload);
        assert_eq!(hash(&buf), Hash::from_hex(HEX1).unwrap());
    }
}
