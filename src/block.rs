//! Block construction, validation, and wire format.

use crate::always::*;
use crate::errors::BlockError;
use crate::payload::Payload;
use crate::pksign::verify_block_signature;
use blake3::{Hash, hash};

const ZERO_HASH: Hash = Hash::from_bytes([0; DIGEST]);

fn check_block_buf(buf: &[u8]) {
    if buf.len() != BLOCK {
        panic!("Need a {BLOCK} byte slice; got {} bytes", buf.len());
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
    pub payload: Payload,
}

impl BlockState {
    pub fn new(
        index: u64,
        block_hash: Hash,
        chain_hash: Hash,
        next_pubkey_hash: Hash,
        payload: Payload,
    ) -> Self {
        Self {
            index,
            block_hash,
            chain_hash,
            next_pubkey_hash,
            payload,
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
            payload: self.payload(),
        }
    }

    fn as_hashable(&self) -> &[u8] {
        &self.buf[HASHABLE_RANGE]
    }

    pub fn as_signable(&self) -> &[u8] {
        &self.buf[SIGNABLE_RANGE]
    }

    pub fn as_signable2(&self) -> &[u8] {
        &self.buf[SIGNABLE2_RANGE]
    }

    pub fn as_signature(&self) -> &[u8] {
        &self.buf[SIGNATURE_RANGE]
    }

    pub fn as_pubkey(&self) -> &[u8] {
        &self.buf[PUBKEY_RANGE]
    }

    pub fn hash(&self) -> Hash {
        get_hash(self.buf, HASH_RANGE)
    }

    pub fn next_pubkey_hash(&self) -> Hash {
        get_hash(self.buf, NEXT_PUBKEY_HASH_RANGE)
    }

    pub fn payload(&self) -> Payload {
        Payload::from_buf(&self.buf[PAYLOAD_RANGE])
    }

    pub fn index(&self) -> u64 {
        get_u64(self.buf, INDEX_RANGE)
    }

    pub fn previous_hash(&self) -> Hash {
        get_hash(self.buf, PREVIOUS_HASH_RANGE)
    }

    pub fn chain_hash(&self) -> Hash {
        get_hash(self.buf, CHAIN_HASH_RANGE)
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

/// Build a new block.
pub struct MutBlock<'a> {
    buf: &'a mut [u8],
}

impl<'a> MutBlock<'a> {
    pub fn new(buf: &'a mut [u8], payload: &Payload) -> Self {
        check_block_buf(buf);
        buf.fill(0);
        payload.write_to_buf(&mut buf[PAYLOAD_RANGE]);
        Self { buf }
    }

    pub fn set_hash(&mut self, block_hash: &Hash) {
        set_hash(self.buf, HASH_RANGE, block_hash);
    }

    pub fn set_next_pubkey_hash(&mut self, next_pubkey_hash: &Hash) {
        set_hash(self.buf, NEXT_PUBKEY_HASH_RANGE, next_pubkey_hash);
    }

    pub fn set_previous(&mut self, prev: &BlockState) {
        set_u64(self.buf, INDEX_RANGE, prev.index + 1);
        set_hash(self.buf, PREVIOUS_HASH_RANGE, &prev.block_hash);
        let chain_hash = prev.effective_chain_hash(); // Don't use prev.chain_hash !
        set_hash(self.buf, CHAIN_HASH_RANGE, &chain_hash);
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

    pub fn as_signable2(&self) -> &[u8] {
        &self.buf[SIGNABLE2_RANGE]
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
    use crate::pksign::{SecretSigner, sign_block};
    use crate::secretseed::Seed;
    use crate::testhelpers::{BitFlipper, HashBitFlipper, random_hash, random_payload};

    const HEX0: &str = "e8014b22e4a5029778ba42f3d3538d6fdd9a912d4406f280f86aeeeb6bdd15b0";
    const HEX1: &str = "50997820b97129d2f50964e3438b2232a9ffe61050c9d32537cc1b863083961b";

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
        let payload = random_payload();
        let bs = BlockState::new(0, h1, h2, h3, payload);
        assert_eq!(bs.effective_chain_hash(), h1);
        let bs = BlockState::new(1, h1, h2, h3, payload);
        assert_eq!(bs.effective_chain_hash(), h2);
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

        buf.extend_from_slice(&[5; 8]); // TIME
        buf.extend_from_slice(&[7; DIGEST]); // STATE_HASH

        buf.extend_from_slice(&[8; 8]); // INDEX
        buf.extend_from_slice(&[9; DIGEST]); // PREVIOUS_HASH
        buf.extend_from_slice(&[10; DIGEST]); // CHAIN_HASH
        buf
    }

    #[test]
    fn test_block_new() {
        let buf: Vec<u8> = vec![0; BLOCK];
        let _block = Block::new(&buf[..]);
    }

    #[test]
    #[should_panic(expected = "Need a 5533 byte slice; got 5532 bytes")]
    fn test_block_new_short_panic() {
        let buf: Vec<u8> = vec![0; BLOCK - 1];
        let _block = Block::new(&buf[..]);
    }

    #[test]
    #[should_panic(expected = "Need a 5533 byte slice; got 5534 bytes")]
    fn test_block_new_long_panic() {
        let buf: Vec<u8> = vec![0; BLOCK + 1];
        let _block = Block::new(&buf[..]);
    }

    #[test]
    #[should_panic(expected = "Need a 5533 byte slice; got 5532 bytes")]
    fn test_block_open_short_panic() {
        let buf: Vec<u8> = vec![0; BLOCK - 1];
        let _block = Block::open(&buf[..]);
    }

    #[test]
    #[should_panic(expected = "Need a 5533 byte slice; got 5534 bytes")]
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
            block.payload(),
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
            let prev = BlockState::new(0, p.block_hash, p.chain_hash, bad, p.payload);
            assert_eq!(
                Block::from_previous(&buf[..], &prev),
                Err(BlockError::PubKeyHash)
            );
        }
        for bad in HashBitFlipper::new(&p.block_hash) {
            let prev = BlockState::new(0, bad, p.chain_hash, p.next_pubkey_hash, p.payload);
            assert_eq!(
                Block::from_previous(&buf[..], &prev),
                Err(BlockError::PreviousHash)
            );
        }
        for bad in HashBitFlipper::new(&p.chain_hash) {
            let prev = BlockState::new(0, p.block_hash, bad, p.next_pubkey_hash, p.payload);
            // Previous `BlockState.chain_hash` only gets checked in 3rd block and beyond:
            assert!(Block::from_previous(&buf[..], &prev).is_ok());
        }
        for bad in BitFlipper::new(&[0; 8]) {
            let bad_index = u64::from_le_bytes(bad.try_into().unwrap());
            let last = BlockState::new(
                bad_index,
                p.block_hash,
                p.chain_hash,
                p.next_pubkey_hash,
                p.payload,
            );
            assert_eq!(
                Block::from_previous(&buf[..], &last),
                Err(BlockError::Index)
            );
        }
    }

    #[test]
    fn test_block_from_previous_3rd() {
        let mut buf = [0; BLOCK];
        let seed = Seed::auto_create().unwrap();
        let chain_hash = sign_block(&mut buf, &seed, &random_payload(), None);
        let tail = Block::from_hash_at_index(&buf, &chain_hash, 0)
            .unwrap()
            .state();

        let seed = seed.auto_advance().unwrap();
        sign_block(&mut buf, &seed, &random_payload(), Some(&tail));
        for bad in HashBitFlipper::new(&chain_hash) {
            let prev =
                BlockState::new(0, tail.block_hash, bad, tail.next_pubkey_hash, tail.payload);
            // Previous `BlockState.chain_hash` only gets checked in 3rd block and beyond:
            assert!(Block::from_previous(&buf[..], &prev).is_ok());
        }
        let tail = Block::from_previous(&buf, &tail).unwrap().state();

        // Sign 3rd block
        let seed = seed.auto_advance().unwrap();
        sign_block(&mut buf, &seed, &random_payload(), Some(&tail));
        assert!(Block::from_previous(&buf, &tail).is_ok());
        for bad in HashBitFlipper::new(&chain_hash) {
            let prev =
                BlockState::new(1, tail.block_hash, bad, tail.next_pubkey_hash, tail.payload);
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
        assert_eq!(block.as_signature(), [2; SIGNATURE]);
        assert_eq!(block.as_pubkey(), [3; PUBKEY]);
    }

    #[test]
    fn test_block_hash_accessors() {
        let buf = new_dummy_block();
        let block = Block::new(&buf[..]);
        assert_eq!(block.hash(), Hash::from_bytes([1; DIGEST]));
        assert_eq!(block.next_pubkey_hash(), Hash::from_bytes([4; DIGEST]));

        assert_eq!(block.payload().time, 361700864190383365);
        assert_eq!(block.payload().state_hash, Hash::from_bytes([7; DIGEST]));

        assert_eq!(block.index(), 578721382704613384);
        assert_eq!(block.previous_hash(), Hash::from_bytes([9; DIGEST]));
        assert_eq!(block.chain_hash(), Hash::from_bytes([10; DIGEST]));
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
        let payload = Payload::new(0, Hash::from_bytes([42; DIGEST]));
        MutBlock::new(&mut buf, &payload);
        assert_eq!(hash(&buf), Hash::from_hex(HEX1).unwrap());
    }
}
