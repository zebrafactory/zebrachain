//! Block construction, validation, and wire format.

use crate::always::*;
use crate::pksign::verify_block_signature;
use blake3::{hash, Hash};
use std::io;

const ZERO_HASH: Hash = Hash::from_bytes([0; DIGEST]);

fn check_block_buf(buf: &[u8]) {
    if buf.len() != BLOCK {
        panic!("Need a {BLOCK} byte slice; got {} bytes", buf.len());
    }
}

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

    /// Chain hash does not match expected external value.
    ChainHash,

    /// Index does not match expected external value (previous block index + 1).
    Index,

    /// First block does not meet 1st block constraints
    FirstBlock,
}

impl BlockError {
    // FIXME: Is there is a Rustier way of doing this? Feedback encouraged.
    pub fn to_io_error(&self) -> io::Error {
        io::Error::other(format!("BlockError::{self:?}"))
    }
}

/// Alias for `Result<Block<'a>, BlockError>`.
pub type BlockResult<'a> = Result<Block<'a>, BlockError>;

/// Contains state from current block needed to validate next block.
#[derive(Clone, Debug, PartialEq)]
pub struct BlockState {
    pub index: u64,
    pub block_hash: Hash,
    pub chain_hash: Hash,
    pub next_pubkey_hash: Hash,
}

impl BlockState {
    pub fn new(index: u64, block_hash: Hash, chain_hash: Hash, next_pubkey_hash: Hash) -> Self {
        Self {
            index,
            block_hash,
            chain_hash,
            next_pubkey_hash,
        }
    }

    pub fn effective_chain_hash(&self) -> Hash {
        if self.index == 0 {
            self.block_hash
        } else {
            self.chain_hash
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
        check_block_buf(buf);
        Self { buf }
    }

    pub fn as_buf(&self) -> &[u8] {
        self.buf
    }

    pub fn open(buf: &'a [u8]) -> BlockResult<'a> {
        let block = Block::new(buf);
        if !block.content_is_valid() {
            Err(BlockError::Content)
        } else if !block.signature_is_valid() {
            Err(BlockError::Signature)
        } else if !block.first_block_is_valid() {
            Err(BlockError::FirstBlock)
        } else {
            Ok(block)
        }
    }

    /// Open and verify a block with `block_hash` at position `index` in the chain.
    ///
    /// This is used when loading the first block (`index=0`), or when resuming from a
    /// [CheckPoint][crate::chain::CheckPoint].
    pub fn from_hash_at_index(buf: &'a [u8], block_hash: &Hash, index: u64) -> BlockResult<'a> {
        let block = Block::open(buf)?;
        if block_hash != &block.hash() {
            Err(BlockError::Hash)
        } else if index != block.index() {
            Err(BlockError::Index)
        } else {
            Ok(block)
        }
    }

    /// Open and verify the block that comes after the previous [BlockState] `prev`.
    ///
    /// This is done when walking the chain for verification (blocks after the first block, or,
    /// when resuming from a checkpoint, blocks after that checkpoint block).
    pub fn from_previous(buf: &'a [u8], prev: &BlockState) -> BlockResult<'a> {
        let block = Block::open(buf)?;
        if block.compute_pubkey_hash() != prev.next_pubkey_hash {
            Err(BlockError::PubKeyHash)
        } else if block.index() != prev.index + 1 {
            Err(BlockError::Index)
        } else if block.previous_hash() != prev.block_hash {
            Err(BlockError::PreviousHash)
        } else if block.chain_hash() != prev.effective_chain_hash() {
            Err(BlockError::ChainHash)
        } else {
            Ok(block)
        }
    }

    pub fn state(&self) -> BlockState {
        BlockState {
            index: self.index(),
            block_hash: self.hash(),
            chain_hash: self.chain_hash(),
            next_pubkey_hash: self.next_pubkey_hash(),
        }
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

    fn as_index(&self) -> &[u8] {
        &self.buf[INDEX_RANGE]
    }

    fn as_auth_hash(&self) -> &[u8] {
        &self.buf[AUTH_HASH_RANGE]
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

    pub fn index(&self) -> u64 {
        u64::from_le_bytes(self.as_index().try_into().unwrap())
    }

    pub fn auth_hash(&self) -> Hash {
        Hash::from_bytes(self.as_auth_hash().try_into().expect("oops"))
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
        verify_block_signature(self)
    }

    fn first_block_is_valid(&self) -> bool {
        if self.index() == 0 {
            self.chain_hash() == ZERO_HASH && self.previous_hash() == ZERO_HASH
        } else {
            true
        }
    }
}

pub struct SigningRequest {
    pub auth_hash: Hash,
    pub state_hash: Hash,
}

impl SigningRequest {
    pub fn new(auth_hash: Hash, state_hash: Hash) -> Self {
        Self {
            auth_hash,
            state_hash,
        }
    }
}

/// Build a new block.
pub struct MutBlock<'a> {
    buf: &'a mut [u8],
}

impl<'a> MutBlock<'a> {
    pub fn new(buf: &'a mut [u8], request: &SigningRequest) -> Self {
        check_block_buf(buf);
        buf.fill(0);
        buf[STATE_HASH_RANGE].copy_from_slice(request.state_hash.as_bytes());
        buf[AUTH_HASH_RANGE].copy_from_slice(request.auth_hash.as_bytes());
        Self { buf }
    }

    pub fn set_hash(&mut self, block_hash: &Hash) {
        self.buf[HASH_RANGE].copy_from_slice(block_hash.as_bytes());
    }

    pub fn set_next_pubkey_hash(&mut self, next_pubkey_hash: &Hash) {
        self.buf[NEXT_PUBKEY_HASH_RANGE].copy_from_slice(next_pubkey_hash.as_bytes());
    }

    pub fn set_previous(&mut self, last: &BlockState) {
        self.buf[INDEX_RANGE].copy_from_slice(&(last.index + 1).to_le_bytes());
        self.buf[PREVIOUS_HASH_RANGE].copy_from_slice(last.block_hash.as_bytes());
        let chain_hash = last.effective_chain_hash(); // Don't use last.chain_hash !
        self.buf[CHAIN_HASH_RANGE].copy_from_slice(chain_hash.as_bytes());
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

    pub fn compute_pubkey_hash(&self) -> Hash {
        hash(&self.buf[PUBKEY_RANGE])
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
    use crate::pksign::{sign_block, SecretSigner};
    use crate::secretseed::Seed;
    use crate::testhelpers::{random_hash, random_request, BitFlipper, HashBitFlipper};

    const HEX0: &str = "4368f1ef39453e8cf1214a90ddf59fb9d94553a46178abd772c5b84f068ed6a8";
    const HEX1: &str = "0934f0ee7a7c41ac69f9e3705a1395d31ddc9a2d81fbdd0b11b70a92535922be";

    #[test]
    fn test_blockerror_to_io_error() {
        assert_eq!(
            format!("{:?}", BlockError::Content.to_io_error()),
            "Custom { kind: Other, error: \"BlockError::Content\" }"
        );
        assert_eq!(
            format!("{:?}", BlockError::Signature.to_io_error()),
            "Custom { kind: Other, error: \"BlockError::Signature\" }"
        );
    }

    #[test]
    fn test_blockstate_effective_chain_hash() {
        let h1 = random_hash();
        let h2 = random_hash();
        let h3 = random_hash();
        let bs = BlockState::new(0, h1, h2, h3);
        assert_eq!(bs.effective_chain_hash(), h1);
        let bs = BlockState::new(1, h1, h2, h3);
        assert_eq!(bs.effective_chain_hash(), h2);
    }

    fn new_expected() -> Hash {
        Hash::from_hex(HEX0).unwrap()
    }

    fn new_valid_block() -> Vec<u8> {
        let mut buf = vec![0; BLOCK];
        let seed = Seed::create(&Hash::from_bytes([69; 32]));
        let secsign = SecretSigner::new(&seed);
        let request = SigningRequest::new(Hash::from_bytes([1; 32]), Hash::from_bytes([2; 32]));
        let mut block = MutBlock::new(&mut buf, &request);
        let last = BlockState::new(
            0,
            Hash::from_bytes([3; 32]),
            ZERO_HASH,
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
        buf.extend_from_slice(&[5; 8]); // INDEX
        buf.extend_from_slice(&[6; DIGEST]); // AUTH_HASH
        buf.extend_from_slice(&[7; DIGEST]); // STATE_HASH
        buf.extend_from_slice(&[10; 8]);
        buf.extend_from_slice(&[8; DIGEST]); // PREVIOUS_HASH
        buf.extend_from_slice(&[9; DIGEST]); // CHAIN_HASH
        buf
    }

    #[test]
    fn test_block_new() {
        let buf: Vec<u8> = vec![0; BLOCK];
        let _block = Block::new(&buf[..]);
    }

    #[test]
    #[should_panic(expected = "Need a 5549 byte slice; got 5548 bytes")]
    fn test_block_new_short_panic() {
        let buf: Vec<u8> = vec![0; BLOCK - 1];
        let _block = Block::new(&buf[..]);
    }

    #[test]
    #[should_panic(expected = "Need a 5549 byte slice; got 5550 bytes")]
    fn test_block_new_long_panic() {
        let buf: Vec<u8> = vec![0; BLOCK + 1];
        let _block = Block::new(&buf[..]);
    }

    #[test]
    #[should_panic(expected = "Need a 5549 byte slice; got 5548 bytes")]
    fn test_block_open_short_panic() {
        let buf: Vec<u8> = vec![0; BLOCK - 1];
        let _block = Block::open(&buf[..]);
    }

    #[test]
    #[should_panic(expected = "Need a 5549 byte slice; got 5550 bytes")]
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
    fn test_block_from_hash_at_index() {
        let buf = new_valid_block();
        let good = Block::open(&buf[..]).unwrap().hash();
        assert!(Block::from_hash_at_index(&buf[..], &good, 1).is_ok());

        // Make sure Block::open() is getting called
        for bad in BitFlipper::new(&buf[..]) {
            assert_eq!(
                Block::from_hash_at_index(&bad[..], &good, 0),
                Err(BlockError::Content)
            );
        }
        for badend in BitFlipper::new(&buf[DIGEST..]) {
            let mut badbuf = [0; BLOCK];
            badbuf[0..DIGEST].copy_from_slice(hash(&badend).as_bytes());
            badbuf[DIGEST..].copy_from_slice(&badend);
            assert_eq!(
                Block::from_hash_at_index(&badbuf, &good, 0),
                Err(BlockError::Signature)
            );
        }

        // Block::from_hash_at_index() specific error
        for bad in HashBitFlipper::new(&good) {
            assert_eq!(
                Block::from_hash_at_index(&buf[..], &bad, 0),
                Err(BlockError::Hash)
            );
        }
    }

    #[test]
    fn test_block_from_previous() {
        let buf = new_valid_block();
        let block = Block::open(&buf[..]).unwrap();
        let state = block.state(); // Cannot append from self
        assert!(Block::from_previous(&buf[..], &state).is_err());
        let p = BlockState::new(
            // Previous block state
            0,
            block.previous_hash(),
            ZERO_HASH,
            block.compute_pubkey_hash(),
        );
        assert!(Block::from_previous(&buf[..], &p).is_ok());

        // Make sure Block::open() is getting called
        for bad in BitFlipper::new(&buf[..]) {
            assert_eq!(Block::from_previous(&bad[..], &p), Err(BlockError::Content));
        }
        for badend in BitFlipper::new(&buf[DIGEST..]) {
            let mut badbuf = [0; BLOCK];
            badbuf[0..DIGEST].copy_from_slice(hash(&badend).as_bytes());
            badbuf[DIGEST..].copy_from_slice(&badend);
            assert_eq!(
                Block::from_previous(&badbuf, &p),
                Err(BlockError::Signature)
            );
        }

        // Block::from_previous() specific errors
        for bad in HashBitFlipper::new(&p.next_pubkey_hash) {
            let prev = BlockState::new(0, p.block_hash, p.chain_hash, bad);
            assert_eq!(
                Block::from_previous(&buf[..], &prev),
                Err(BlockError::PubKeyHash)
            );
        }
        for bad in HashBitFlipper::new(&p.block_hash) {
            let prev = BlockState::new(0, bad, p.chain_hash, p.next_pubkey_hash);
            assert_eq!(
                Block::from_previous(&buf[..], &prev),
                Err(BlockError::PreviousHash)
            );
        }
        for bad in HashBitFlipper::new(&p.chain_hash) {
            let prev = BlockState::new(0, p.block_hash, bad, p.next_pubkey_hash);
            // Previous `BlockState.chain_hash` only gets checked in 3rd block and beyond:
            assert!(Block::from_previous(&buf[..], &prev).is_ok());
        }
        for bad in BitFlipper::new(&[0; 8]) {
            let bad_index = u64::from_le_bytes(bad.try_into().unwrap());
            let last = BlockState::new(bad_index, p.block_hash, p.chain_hash, p.next_pubkey_hash);
            assert_eq!(
                Block::from_previous(&buf[..], &last),
                Err(BlockError::Index)
            );
        }
    }

    #[test]
    fn test_block_from_previous_3rd() {
        let mut buf = [0; BLOCK];
        let seed = Seed::auto_create();
        let chain_hash = sign_block(&mut buf, &seed, &random_request(), None);
        let tail = Block::from_hash_at_index(&buf, &chain_hash, 0)
            .unwrap()
            .state();

        let seed = seed.auto_advance();
        sign_block(&mut buf, &seed, &random_request(), Some(&tail));
        for bad in HashBitFlipper::new(&chain_hash) {
            let prev = BlockState::new(0, tail.block_hash, bad, tail.next_pubkey_hash);
            // Previous `BlockState.chain_hash` only gets checked in 3rd block and beyond:
            assert!(Block::from_previous(&buf[..], &prev).is_ok());
        }
        let tail = Block::from_previous(&buf, &tail).unwrap().state();

        // Sign 3rd block
        let seed = seed.auto_advance();
        sign_block(&mut buf, &seed, &random_request(), Some(&tail));
        assert!(Block::from_previous(&buf, &tail).is_ok());
        for bad in HashBitFlipper::new(&chain_hash) {
            let prev = BlockState::new(1, tail.block_hash, bad, tail.next_pubkey_hash);
            assert_eq!(
                Block::from_previous(&buf[..], &prev),
                Err(BlockError::ChainHash)
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
        assert_eq!(block.as_index(), [5; 8]);
        assert_eq!(block.as_auth_hash(), [6; DIGEST]);
        assert_eq!(block.as_state_hash(), [7; DIGEST]);
        assert_eq!(block.as_previous_hash(), [8; DIGEST]);
        assert_eq!(block.as_chain_hash(), [9; DIGEST]);
    }

    #[test]
    fn test_block_hash_accessors() {
        let buf = new_dummy_block();
        let block = Block::new(&buf[..]);
        assert_eq!(block.hash(), Hash::from_bytes([1; DIGEST]));
        assert_eq!(block.next_pubkey_hash(), Hash::from_bytes([4; DIGEST]));
        assert_eq!(block.index(), 361700864190383365);
        assert_eq!(block.auth_hash(), Hash::from_bytes([6; DIGEST]));
        assert_eq!(block.state_hash(), Hash::from_bytes([7; DIGEST]));
        assert_eq!(block.previous_hash(), Hash::from_bytes([8; DIGEST]));
        assert_eq!(block.chain_hash(), Hash::from_bytes([9; DIGEST]));
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
    fn test_block_signature_is_valid() {
        let good = new_valid_block();
        let block = Block::new(&good[..]);
        assert!(block.signature_is_valid());
        for bad in BitFlipper::new(&good[..]) {
            let block = Block::new(&bad[..]);
            if bad[HASH_RANGE] == good[HASH_RANGE] {
                assert!(!block.signature_is_valid());
            } else {
                assert!(block.signature_is_valid());
                assert!(!block.content_is_valid());
            }
        }
    }

    #[test]
    fn test_block_first_block_is_valid() {
        let buf = [0; BLOCK];
        assert!(Block::new(&buf).first_block_is_valid());
        for bad_hash in HashBitFlipper::new(&ZERO_HASH) {
            let mut bad = buf.clone();
            bad[CHAIN_HASH_RANGE].copy_from_slice(bad_hash.as_bytes());
            assert!(!Block::new(&bad).first_block_is_valid());
            bad[INDEX_RANGE].copy_from_slice(&1u64.to_le_bytes());
            assert!(Block::new(&bad).first_block_is_valid());

            let mut bad = buf.clone();
            bad[PREVIOUS_HASH_RANGE].copy_from_slice(bad_hash.as_bytes());
            assert!(!Block::new(&bad).first_block_is_valid());
            bad[INDEX_RANGE].copy_from_slice(&1u64.to_le_bytes());
            assert!(Block::new(&bad).first_block_is_valid());
        }
    }

    #[test]
    fn test_mutblock_new() {
        let mut buf = [27; BLOCK];
        let request = SigningRequest::new(
            Hash::from_bytes([42; DIGEST]),
            Hash::from_bytes([69; DIGEST]),
        );
        MutBlock::new(&mut buf, &request);
        assert_eq!(hash(&buf), Hash::from_hex(HEX1).unwrap());
    }
}
