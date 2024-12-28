//! Block construction, validation, and wire format.

use crate::pksign::verify_signature;
use crate::tunable::*;
use blake3::{hash, Hash};

/// Expresses different error conditions hit during block validation.
#[derive(Debug, PartialEq)]
pub enum BlockError {
    /// Hash of block content does not match hash in block.
    Content,

    /// Public key or signature is invalid.
    Signature,

    /// Hash in block does not match expected external value.
    Hash,

    /// Hash of public key bytes does not match expected external value.
    PubKeyHash,

    /// Previous hash does not match expected external value.
    PreviousHash,

    /// Hash of chain namespace is wrong
    ChainHash,
}

/// Alias for `Result<Block<'a>, BlockError>`.
pub type BlockResult<'a> = Result<Block<'a>, BlockError>;

/// Contains state from current block needed to validate next block.
#[derive(Debug, PartialEq)]
pub struct BlockState {
    pub counter: u128,
    pub block_hash: Hash,
    pub chain_hash: Hash,
    pub next_pubkey_hash: Hash,
}

impl BlockState {
    pub fn new(block_hash: Hash, chain_hash: Hash, next_pubkey_hash: Hash) -> Self {
        Self {
            counter: 0, // FIXME: Add counter to block wire format
            block_hash,
            chain_hash,
            next_pubkey_hash,
        }
    }
}

/// Validate block wire format, extract items from the same.
#[derive(Debug, PartialEq)]
pub struct Block<'a> {
    buf: &'a [u8],
}

impl<'a> Block<'a> {
    fn new(buf: &'a [u8]) -> Self {
        if buf.len() != BLOCK {
            panic!("Need a {BLOCK} byte slice; got {} bytes", buf.len());
        }
        Self { buf }
    }

    pub fn open(buf: &'a [u8]) -> BlockResult<'a> {
        let block = Block::new(buf);
        if !block.content_is_valid() {
            Err(BlockError::Content)
        } else if !block.signature_is_valid() {
            Err(BlockError::Signature)
        } else {
            Ok(block)
        }
    }

    pub fn from_hash(buf: &'a [u8], h: Hash) -> BlockResult<'a> {
        let block = Block::open(buf)?;
        if h != block.hash() {
            Err(BlockError::Hash)
        } else {
            Ok(block)
        }
    }

    pub fn from_previous(buf: &'a [u8], last: &BlockState) -> BlockResult<'a> {
        let block = Block::open(buf)?;
        if block.compute_pubkey_hash() != last.next_pubkey_hash {
            Err(BlockError::PubKeyHash)
        } else if block.previous_hash() != last.block_hash {
            Err(BlockError::PreviousHash)
        } else if block.chain_hash() != last.chain_hash {
            Err(BlockError::ChainHash)
        } else {
            Ok(block)
        }
    }

    pub fn state(&self) -> BlockState {
        BlockState::new(self.hash(), self.chain_hash(), self.next_pubkey_hash())
    }

    fn as_hashable(&self) -> &[u8] {
        &self.buf[HASHABLE_RANGE]
    }

    pub fn as_signable(&self) -> &[u8] {
        &self.buf[SIGNABLE_RANGE]
    }

    fn as_hash(&self) -> &[u8] {
        &self.buf[HASH_RANGE]
    }

    pub fn as_signature(&self) -> &[u8] {
        &self.buf[SIGNATURE_RANGE]
    }

    pub fn as_pubkey(&self) -> &[u8] {
        &self.buf[PUBKEY_RANGE]
    }

    fn as_next_pubkey_hash(&self) -> &[u8] {
        &self.buf[NEXT_PUBKEY_HASH_RANGE]
    }

    fn as_state_hash(&self) -> &[u8] {
        &self.buf[STATE_HASH_RANGE]
    }

    fn as_previous_hash(&self) -> &[u8] {
        &self.buf[PREVIOUS_HASH_RANGE]
    }

    fn as_chain_hash(&self) -> &[u8] {
        &self.buf[CHAIN_HASH_RANGE]
    }

    pub fn hash(&self) -> Hash {
        Hash::from_bytes(self.as_hash().try_into().expect("oops"))
    }

    pub fn next_pubkey_hash(&self) -> Hash {
        Hash::from_bytes(self.as_next_pubkey_hash().try_into().expect("oops"))
    }

    pub fn state_hash(&self) -> Hash {
        Hash::from_bytes(self.as_state_hash().try_into().expect("oops"))
    }

    pub fn previous_hash(&self) -> Hash {
        Hash::from_bytes(self.as_previous_hash().try_into().expect("oops"))
    }

    pub fn chain_hash(&self) -> Hash {
        Hash::from_bytes(self.as_chain_hash().try_into().expect("oops"))
    }

    fn compute_hash(&self) -> Hash {
        hash(self.as_hashable())
    }

    fn compute_pubkey_hash(&self) -> Hash {
        hash(self.as_pubkey())
    }

    fn content_is_valid(&self) -> bool {
        self.compute_hash() == self.hash()
    }

    fn signature_is_valid(&self) -> bool {
        verify_signature(self)
    }
}

/// Build a new block.
pub struct MutBlock<'a> {
    buf: &'a mut [u8],
}

impl<'a> MutBlock<'a> {
    pub fn new(buf: &'a mut [u8], state_hash: &Hash) -> Self {
        if buf.len() != BLOCK {
            panic!("Need a {BLOCK} byte slice; got {} bytes", buf.len());
        }
        buf.fill(0);
        buf[STATE_HASH_RANGE].copy_from_slice(state_hash.as_bytes());
        Self { buf }
    }

    pub fn set_hash(&mut self, block_hash: &Hash) {
        self.buf[HASH_RANGE].copy_from_slice(block_hash.as_bytes());
    }

    pub fn set_next_pubkey_hash(&mut self, next_pubkey_hash: &Hash) {
        self.buf[NEXT_PUBKEY_HASH_RANGE].copy_from_slice(next_pubkey_hash.as_bytes());
    }

    pub fn set_previous(&mut self, last: &BlockState) {
        // Either both of these get set or, in the case of the first block, neither are set.
        self.buf[PREVIOUS_HASH_RANGE].copy_from_slice(last.block_hash.as_bytes());
        self.buf[CHAIN_HASH_RANGE].copy_from_slice(last.chain_hash.as_bytes());
    }

    pub fn as_mut_signature(&mut self) -> &mut [u8] {
        &mut self.buf[SIGNATURE_RANGE]
    }

    pub fn as_mut_pubkey(&mut self) -> &mut [u8] {
        &mut self.buf[PUBKEY_RANGE]
    }

    pub fn as_hashable(&self) -> &[u8] {
        &self.buf[HASHABLE_RANGE]
    }

    pub fn as_signable(&self) -> &[u8] {
        &self.buf[SIGNABLE_RANGE]
    }

    pub fn finalize(mut self) -> Hash {
        let block_hash = hash(self.as_hashable());
        self.set_hash(&block_hash);
        block_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::misc::BitFlipper;
    use crate::pksign::SecretSigner;
    use crate::secretseed::Seed;

    const EXPECTED: &str = "1235a30e9a3086fa131087c5683eeaa5e4733dfa28fe610d4ed2b76e114011c7";

    fn new_expected() -> Hash {
        Hash::from_hex(EXPECTED).unwrap()
    }

    fn new_valid_block() -> Vec<u8> {
        let mut buf = vec![0; BLOCK];
        let seed = Seed::create(&[69; 32]);
        let secsign = SecretSigner::new(&seed);
        let state_hash = Hash::from_bytes([2; 32]);
        let mut block = MutBlock::new(&mut buf, &state_hash);
        let last = BlockState::new(
            Hash::from_bytes([3; 32]),
            Hash::from_bytes([4; 32]),
            Hash::from_bytes([5; 32]),
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
        buf.extend_from_slice(&[5; DIGEST]); // STATE_HASH
        buf.extend_from_slice(&[6; DIGEST]); // PREVIOUS_HASH
        buf.extend_from_slice(&[7; DIGEST]); // CHAIN_HASH
        buf
    }

    #[test]
    fn test_block_new() {
        let buf: Vec<u8> = vec![0; BLOCK];
        let _block = Block::new(&buf[..]);
    }

    #[test]
    #[should_panic(expected = "Need a 256 byte slice; got 255 bytes")]
    fn test_block_new_short_panic() {
        let buf: Vec<u8> = vec![0; BLOCK - 1];
        let _block = Block::new(&buf[..]);
    }

    #[test]
    #[should_panic(expected = "Need a 256 byte slice; got 257 bytes")]
    fn test_block_new_long_panic() {
        let buf: Vec<u8> = vec![0; BLOCK + 1];
        let _block = Block::new(&buf[..]);
    }

    #[test]
    #[should_panic(expected = "Need a 256 byte slice; got 255 bytes")]
    fn test_block_open_short_panic() {
        let buf: Vec<u8> = vec![0; BLOCK - 1];
        let _block = Block::open(&buf[..]);
    }

    #[test]
    #[should_panic(expected = "Need a 256 byte slice; got 257 bytes")]
    fn test_block_open_long_panic() {
        let buf: Vec<u8> = vec![0; BLOCK + 1];
        let _block = Block::open(&buf[..]);
    }

    #[test]
    fn test_block_open() {
        let buf = new_valid_block();
        assert!(Block::open(&buf[..]).is_ok());
        for bad in BitFlipper::new(&buf[..]) {
            assert_eq!(Block::open(&bad[..]), Err(BlockError::Content));
        }
        let mut bad = vec![0; BLOCK];
        for end in BitFlipper::new(&buf[HASHABLE_RANGE]) {
            let h = hash(&end[..]);
            bad[HASH_RANGE].copy_from_slice(h.as_bytes());
            bad[HASHABLE_RANGE].copy_from_slice(&end[..]);
            assert_eq!(Block::open(&bad[..]), Err(BlockError::Signature));
        }
    }

    #[test]
    fn test_block_from_hash() {
        let buf = new_valid_block();
        let good = Block::open(&buf[..]).unwrap().hash();
        assert!(Block::from_hash(&buf[..], good).is_ok());
        for bad in BitFlipper::new(good.as_bytes()) {
            let bytes: [u8; 32] = bad[..].try_into().unwrap();
            let h = Hash::from_bytes(bytes);
            assert_eq!(Block::from_hash(&buf[..], h), Err(BlockError::Hash));
        }
    }

    #[test]
    fn test_block_from_previous() {
        let buf = new_valid_block();
        let block = Block::open(&buf[..]).unwrap();
        let state = block.state(); // Cannot append from self
        assert!(Block::from_previous(&buf[..], &state).is_err());
        let state = BlockState::new(
            block.previous_hash(),
            block.chain_hash(),
            block.compute_pubkey_hash(),
        );
        assert!(Block::from_previous(&buf[..], &state).is_ok());

        let next_pubkey_hash = block.compute_pubkey_hash();
        let previous_hash = block.previous_hash();
        for bad in BitFlipper::new(next_pubkey_hash.as_bytes()) {
            let bytes: [u8; 32] = bad[..].try_into().unwrap();
            let h = Hash::from_bytes(bytes);
            let state = BlockState::new(previous_hash, block.chain_hash(), h);
            assert_eq!(
                Block::from_previous(&buf[..], &state),
                Err(BlockError::PubKeyHash)
            );
        }
        for bad in BitFlipper::new(previous_hash.as_bytes()) {
            let bytes: [u8; 32] = bad[..].try_into().unwrap();
            let h = Hash::from_bytes(bytes);
            let state = BlockState::new(h, block.chain_hash(), next_pubkey_hash);
            assert_eq!(
                Block::from_previous(&buf[..], &state),
                Err(BlockError::PreviousHash)
            );
        }
    }

    #[test]
    fn test_block_as_fns() {
        let buf = new_dummy_block();
        let block = Block::new(&buf[..]);
        assert_eq!(block.as_hash(), [1; DIGEST]);
        assert_eq!(block.as_signature(), [2; SIGNATURE]);
        assert_eq!(block.as_pubkey(), [3; PUBKEY]);
        assert_eq!(block.as_next_pubkey_hash(), [4; DIGEST]);
        assert_eq!(block.as_state_hash(), [5; DIGEST]);
        assert_eq!(block.as_previous_hash(), [6; DIGEST]);
        assert_eq!(block.as_chain_hash(), [7; DIGEST]);
    }

    #[test]
    fn test_block_hash_accessors() {
        let buf = new_dummy_block();
        let block = Block::new(&buf[..]);
        assert_eq!(block.hash(), Hash::from_bytes([1; DIGEST]));
        assert_eq!(block.next_pubkey_hash(), Hash::from_bytes([4; DIGEST]));
        assert_eq!(block.state_hash(), Hash::from_bytes([5; DIGEST]));
        assert_eq!(block.previous_hash(), Hash::from_bytes([6; DIGEST]));
        assert_eq!(block.chain_hash(), Hash::from_bytes([7; DIGEST]));
    }

    #[test]
    fn test_block_as_hashable() {
        let buf = new_dummy_block();
        let block = Block::new(&buf[..]);
        assert_eq!(block.as_hashable(), &buf[DIGEST..]);
    }

    #[test]
    fn block_as_signable() {
        let buf = new_dummy_block();
        let block = Block::new(&buf[..]);
        assert_eq!(block.as_signable(), &buf[DIGEST + SIGNATURE..]);
    }

    #[test]
    fn test_block_compute_hash() {
        let buf = new_dummy_block();
        let block = Block::new(&buf[..]);
        let hash = block.compute_hash();
        assert_eq!(hash, new_expected());
    }

    #[test]
    fn test_block_content_is_valid() {
        let good = new_valid_block();
        let block = Block::new(&good[..]);
        assert!(block.content_is_valid());
        for bad in BitFlipper::new(&good[..]) {
            let block = Block::new(&bad[..]);
            assert!(!block.content_is_valid());
        }
    }

    #[test]
    fn test_block_signature_is_value() {
        let good = new_valid_block();
        let block = Block::new(&good[..]);
        assert!(block.signature_is_valid());
        for bad in BitFlipper::new(&good[..]) {
            let block = Block::new(&bad[..]);
            if bad[HASH_RANGE] == good[HASH_RANGE] {
                assert!(!block.signature_is_valid());
            } else {
                assert!(block.signature_is_valid());
            }
        }
    }

    #[test]
    fn test_mutblock_new() {
        let mut buf = [42; BLOCK];
        let state_hash = Hash::from_bytes([69; DIGEST]);
        let mut block = MutBlock::new(&mut buf, &state_hash);
        assert_eq!(
            buf,
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 69, 69, 69, 69, 69, 69,
                69, 69, 69, 69, 69, 69, 69, 69, 69, 69, 69, 69, 69, 69, 69, 69, 69, 69, 69, 69, 69,
                69, 69, 69, 69, 69, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }
}
