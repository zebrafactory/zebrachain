//! Block construction, validation, and wire format.

use crate::always::*;
use crate::pksign::{SecretSigner, verify_block_signature};
use crate::{BlockError, Hash, Payload, Seed};

/// Check point a chain for fast reload.
pub struct CheckPoint {
    /// Chain hash
    pub chain_hash: Hash,

    /// Block hash
    pub block_hash: Hash,

    /// Block-wise position in chain, starting from zero.
    pub block_index: u128,
}

impl CheckPoint {
    /// Create a checkpoint.
    pub fn new(chain_hash: Hash, block_hash: Hash, block_index: u128) -> Self {
        Self {
            chain_hash,
            block_hash,
            block_index,
        }
    }

    /// Downcast index to u64, panic if we can't..
    ///
    /// FIXME SOON: Quick, before someone has a ZebraChain that passes 2^64 blocks, we need a
    /// distributed storage backend that can actually handle a chain that long.
    ///
    /// Aside: We actually have a considerable amount of time to fix this 😎
    pub fn index_as_u64(&self) -> u64 {
        self.block_index.try_into().unwrap()
    }
}

fn check_block_buf(buf: &[u8]) {
    if buf.len() != BLOCK {
        panic!("Need a {BLOCK} byte slice; got {} bytes", buf.len());
    }
}

/// Contains state from current block needed to validate next block, plus the payload.
///
/// This struct includes everything from the block buffer except the signature and public key,
/// both of which are quite large for ML-DSA (and aren't needed by higher level code).
#[derive(Clone, Debug, PartialEq)]
pub struct BlockState {
    /// Block-wise position in chain, starting from zero.
    pub block_index: u128,

    /// Hash of this block.
    pub block_hash: Hash,

    /// Hash of first block in chain.
    ///
    /// If index is 0 (first block), this field is zeros.
    pub chain_hash: Hash,

    /// Hash of previous block.
    ///
    /// If index is 0 (first block), this field is zeros.
    pub previous_hash: Hash,

    /// Hash of the public key that will be used when signing the next block.
    pub next_pubkey_hash: Hash,

    /// The signed content.
    pub payload: Payload,
}

impl BlockState {
    /// Construct a new [BlockState].
    pub fn new(
        block_index: u128,
        block_hash: Hash,
        chain_hash: Hash,
        previous_hash: Hash,
        next_pubkey_hash: Hash,
        payload: Payload,
    ) -> Self {
        Self {
            block_index,
            block_hash,
            chain_hash,
            previous_hash,
            next_pubkey_hash,
            payload,
        }
    }

    /// Returns the block_hash if the index is 0, otherwise the chain hash.
    ///
    /// A ZebraChain is identified by its "chain hash", which is the hash of the first block in
    /// the chain. The chain hash is likewise included in the block as a back reference for blocks
    /// after the first block.
    ///
    /// If this is the first block (block_index is 0), the chain hash is all zeros.
    pub fn effective_chain_hash(&self) -> Hash {
        if self.block_index == 0 {
            self.block_hash
        } else {
            self.chain_hash
        }
    }

    /// Create the checkpoint corresponding to this block.
    pub fn to_checkpoint(&self) -> CheckPoint {
        CheckPoint {
            chain_hash: self.effective_chain_hash(),
            block_hash: self.block_hash,
            block_index: self.block_index,
        }
    }

    // Warning: this does ZERO validation!
    fn from_buf(buf: &[u8]) -> Self {
        Self {
            block_index: u128::from_le_bytes(buf[INDEX_RANGE].try_into().unwrap()),
            block_hash: Hash::from_slice(&buf[HASH_RANGE]).unwrap(),
            chain_hash: Hash::from_slice(&buf[CHAIN_HASH_RANGE]).unwrap(),
            previous_hash: Hash::from_slice(&buf[PREVIOUS_HASH_RANGE]).unwrap(),
            next_pubkey_hash: Hash::from_slice(&buf[NEXT_PUBKEY_HASH_RANGE]).unwrap(),
            payload: Payload::from_buf(&buf[PAYLOAD_RANGE]),
        }
    }

    fn first_block_is_valid(&self) -> bool {
        if self.block_index == 0 {
            self.chain_hash.is_zeros() && self.previous_hash.is_zeros()
        } else {
            true
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
        } else if !state.first_block_is_valid() {
            Err(BlockError::FirstBlock)
        } else {
            Ok(state)
        }
    }

    /// Open and verify a block with `block_hash` at position `block_index` in the chain.
    pub fn from_hash_at_index(
        &self,
        block_hash: &Hash,
        block_index: u128,
    ) -> Result<BlockState, BlockError> {
        let state = self.open()?;
        if block_hash != &state.block_hash {
            Err(BlockError::BlockHash)
        } else if block_index != state.block_index {
            Err(BlockError::Index)
        } else {
            Ok(state)
        }
    }

    /// Read and verify block from a checkpoint.
    pub fn from_checkpoint(&self, checkpoint: &CheckPoint) -> Result<BlockState, BlockError> {
        let state = self.from_hash_at_index(&checkpoint.block_hash, checkpoint.block_index)?;
        if checkpoint.chain_hash != state.effective_chain_hash() {
            Err(BlockError::ChainHash)
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
        } else if state.block_index != prev.block_index + 1 {
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
        Hash::compute(self.as_hashable())
    }

    fn compute_pubkey_hash(&self) -> Hash {
        Hash::compute(self.as_pubkey())
    }

    fn signature_is_valid(&self) -> bool {
        verify_block_signature(self)
    }
}

/// Builds up a new block in a buffer.
///
/// # Examples
///
/// ```
/// use zf_zebrachain::{BLOCK, DIGEST, Block, Hash, MutBlock, Payload, Seed};
///
/// // Build, sign, and finalize a new block like this:
/// let mut buf = [0; BLOCK];
/// let seed = Seed::generate().unwrap();
/// let payload = Payload::new(123, Hash::from_bytes([69; DIGEST]));
/// let mut block = MutBlock::new(&mut buf, &payload);
/// block.sign(&seed);
/// let block_hash = block.finalize();
///
/// // And then read out the block state like this:
/// let block = Block::new(&buf);
/// let state = block.from_hash_at_index(&block_hash, 0).unwrap();
/// assert_eq!(state.payload, payload);
/// ```
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
        self.buf[INDEX_RANGE].copy_from_slice(&(prev.block_index + 1).to_le_bytes());
        self.buf[PREVIOUS_HASH_RANGE].copy_from_slice(prev.block_hash.as_bytes());
        let chain_hash = prev.effective_chain_hash(); // Don't use prev.chain_hash !
        self.buf[CHAIN_HASH_RANGE].copy_from_slice(chain_hash.as_bytes());
    }

    // Set hash of the public key that will be used for siging the next block.
    pub(crate) fn set_next_pubkey_hash(&mut self, next_pubkey_hash: &Hash) {
        self.buf[NEXT_PUBKEY_HASH_RANGE].copy_from_slice(next_pubkey_hash.as_bytes());
    }

    /// Sign block using seed.
    ///
    /// This sets the `pubkey` and `next_pubkey_hash` fields, computes the signature, and then
    /// sets the `signature` field.
    pub fn sign(&mut self, seed: &Seed) {
        let signer = SecretSigner::new(seed, self.block_index());
        signer.sign(self);
    }

    /// Finalize the block (sets and returns block hash).
    pub fn finalize(self) -> Hash {
        let block_hash = Hash::compute(&self.buf[HASHABLE_RANGE]);
        self.buf[HASH_RANGE].copy_from_slice(block_hash.as_bytes());
        block_hash
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
        Hash::compute(&self.buf[PUBKEY_RANGE])
    }

    fn block_index(&self) -> u128 {
        u128::from_le_bytes(self.buf[INDEX_RANGE].try_into().unwrap())
    }
}

/// Sign a block buffer.
///
/// # Examples
///
/// ```
/// use zf_zebrachain::{BLOCK, DIGEST, Hash, Payload, Seed, sign_block};
/// let mut buf = [0; BLOCK];
/// let seed = Seed::generate().unwrap();
/// let payload = Payload::new(123, Hash::from_bytes([69; DIGEST]));
/// let block_hash = sign_block(&mut buf, &seed, &payload, None);
/// ```
pub fn sign_block(
    buf: &mut [u8],
    seed: &Seed,
    payload: &Payload,
    prev: Option<&BlockState>,
) -> Hash {
    let mut block = MutBlock::new(buf, payload);
    if let Some(prev) = prev {
        block.set_previous(prev);
    }
    block.sign(seed);
    if let Some(prev) = prev {
        assert_eq!(prev.next_pubkey_hash, block.compute_pubkey_hash());
    }
    block.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pksign::SecretSigner;
    use crate::testhelpers::{
        BitFlipper, HashBitFlipper, U128BitFlipper, random_hash, random_payload,
    };
    use crate::{Secret, Seed};
    use getrandom;

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
    fn test_blockstate_to_checkpoint() {
        // when block_index == 0
        let bs = BlockState::new(
            0,             // block_index
            random_hash(), // block_hash
            random_hash(), // chain_hash
            random_hash(), // previous_hash
            random_hash(), // next_pubkey_hash
            random_payload(),
        );
        let checkpoint = bs.to_checkpoint();
        assert_eq!(checkpoint.block_index, 0);
        assert_eq!(checkpoint.block_hash, bs.block_hash);
        assert_eq!(checkpoint.chain_hash, bs.block_hash); // Only on 1st block

        // when block_index > 0
        let bs = BlockState::new(
            1,             // block_index
            random_hash(), // block_hash
            random_hash(), // chain_hash
            random_hash(), // previous_hash
            random_hash(), // next_pubkey_hash
            random_payload(),
        );
        let checkpoint = bs.to_checkpoint();
        assert_eq!(checkpoint.block_index, bs.block_index);
        assert_eq!(checkpoint.block_hash, bs.block_hash);
        assert_eq!(checkpoint.chain_hash, bs.chain_hash);
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
            block_index: 5337762618367662171974503645988520964,
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

    #[test]
    fn test_blockstate_first_block_is_valid() {
        let bs = BlockState {
            block_index: 0,
            block_hash: Hash::from_bytes([1; DIGEST]),
            chain_hash: Hash::from_bytes([5; DIGEST]),
            previous_hash: Hash::from_bytes([6; DIGEST]),
            next_pubkey_hash: Hash::from_bytes([2; DIGEST]),
            payload: Payload::new(
                4003321963775746628980877734491390723,
                Hash::from_bytes([3; DIGEST]),
            ),
        };
        assert!(!bs.first_block_is_valid());

        let bs = BlockState {
            block_index: 0,
            block_hash: Hash::from_bytes([1; DIGEST]),
            chain_hash: Hash::from_bytes([5; DIGEST]),
            previous_hash: Hash::from_bytes([0; DIGEST]), // ZERO_HASH
            next_pubkey_hash: Hash::from_bytes([2; DIGEST]),
            payload: Payload::new(
                4003321963775746628980877734491390723,
                Hash::from_bytes([3; DIGEST]),
            ),
        };
        assert!(!bs.first_block_is_valid());

        let bs = BlockState {
            block_index: 0,
            block_hash: Hash::from_bytes([1; DIGEST]),
            chain_hash: Hash::from_bytes([0; DIGEST]), // ZERO_HASH
            previous_hash: Hash::from_bytes([6; DIGEST]),
            next_pubkey_hash: Hash::from_bytes([2; DIGEST]),
            payload: Payload::new(
                4003321963775746628980877734491390723,
                Hash::from_bytes([3; DIGEST]),
            ),
        };
        assert!(!bs.first_block_is_valid());

        let bs = BlockState {
            block_index: 0,
            block_hash: Hash::from_bytes([1; DIGEST]),
            chain_hash: Hash::from_bytes([0; DIGEST]), // ZERO_HASH
            previous_hash: Hash::from_bytes([0; DIGEST]), // ZERO_HASH
            next_pubkey_hash: Hash::from_bytes([2; DIGEST]),
            payload: Payload::new(
                4003321963775746628980877734491390723,
                Hash::from_bytes([3; DIGEST]),
            ),
        };
        assert!(bs.first_block_is_valid());

        let bs = BlockState {
            block_index: 1,
            block_hash: Hash::from_bytes([1; DIGEST]),
            chain_hash: Hash::from_bytes([5; DIGEST]),
            previous_hash: Hash::from_bytes([6; DIGEST]),
            next_pubkey_hash: Hash::from_bytes([2; DIGEST]),
            payload: Payload::new(
                4003321963775746628980877734491390723,
                Hash::from_bytes([3; DIGEST]),
            ),
        };
        assert!(bs.first_block_is_valid());
    }

    fn new_expected() -> Hash {
        Hash::from_hex(
            "6ceb2e83040898f92123422c87e27100649f2bf982b4eec23cdb467958790302abd18796b3abc150",
        )
        .unwrap()
    }

    fn new_valid_block() -> Vec<u8> {
        let mut buf = vec![0; BLOCK];
        let seed = Seed::create(&Secret::from_bytes([69; SECRET]));
        let secsign = SecretSigner::new(&seed, 1);
        let payload = Payload::new(0, Hash::from_bytes([1; DIGEST]));
        let mut block = MutBlock::new(&mut buf, &payload);
        let last = BlockState::new(
            0,
            Hash::from_bytes([3; DIGEST]),
            Hash::from_bytes([0; DIGEST]), // ZERO_HASH
            Hash::from_bytes([0; DIGEST]), // ZERO_HASH
            Hash::from_bytes([5; DIGEST]),
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
    #[should_panic(expected = "Need a 4060 byte slice; got 4059 bytes")]
    fn test_block_new_short_panic() {
        let buf: Vec<u8> = vec![0; BLOCK - 1];
        let _block = Block::new(&buf);
    }

    #[test]
    #[should_panic(expected = "Need a 4060 byte slice; got 4061 bytes")]
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
            let h = Hash::compute(&end);
            bad[HASH_RANGE].copy_from_slice(h.as_bytes());
            bad[HASHABLE_RANGE].copy_from_slice(&end);
            assert_eq!(Block::new(&bad).open(), Err(BlockError::Signature));
        }

        // Test when a single bit is set in ether the chain_hash or previous_hash fields
        let seed = Seed::generate().unwrap();
        let payload = random_payload();
        let mut buf = [0; BLOCK];
        for bad in BitFlipper::new(&[0; DIGEST * 2]) {
            let mut block = MutBlock::new(&mut buf, &payload);
            block.buf[BLOCK - DIGEST * 2..].copy_from_slice(&bad);
            block.sign(&seed);
            let _block_hash = block.finalize();
            assert_eq!(Block::new(&buf).open(), Err(BlockError::FirstBlock));
        }
    }

    #[test]
    fn test_block_from_hash_at_index() {
        let buf = new_valid_block();
        let state = Block::new(&buf).open().unwrap();
        let good = state.block_hash;
        assert_eq!(Block::new(&buf).from_hash_at_index(&good, 1), Ok(state));

        // Make sure Block::open() is getting called
        for bad in BitFlipper::new(&buf) {
            assert_eq!(
                Block::new(&bad).from_hash_at_index(&good, 1),
                Err(BlockError::Content)
            );
        }
        for badend in BitFlipper::new(&buf[DIGEST..]) {
            let mut badbuf = [0; BLOCK];
            badbuf[0..DIGEST].copy_from_slice(Hash::compute(&badend).as_bytes());
            badbuf[DIGEST..].copy_from_slice(&badend);
            assert_eq!(
                Block::new(&badbuf).from_hash_at_index(&good, 1),
                Err(BlockError::Signature)
            );
        }

        // Test Block::from_hash_at_index() specific errors
        for bad in HashBitFlipper::new(&good) {
            assert_eq!(
                Block::new(&buf).from_hash_at_index(&bad, 1),
                Err(BlockError::BlockHash)
            );
        }
        for bad_index in U128BitFlipper::new(1) {
            assert_eq!(
                Block::new(&buf).from_hash_at_index(&good, bad_index),
                Err(BlockError::Index)
            );
        }
    }

    #[test]
    fn test_block_from_checkpoint() {
        let buf = new_valid_block();
        let state = Block::new(&buf).open().unwrap();
        let checkpoint = state.to_checkpoint();
        assert_eq!(
            Block::new(&buf).from_checkpoint(&checkpoint).unwrap(),
            state
        );

        // Make sure Block::open() is getting called
        for bad_buf in BitFlipper::new(&buf) {
            assert_eq!(
                Block::new(&bad_buf).from_checkpoint(&checkpoint),
                Err(BlockError::Content)
            );
        }
        for badend in BitFlipper::new(&buf[DIGEST..]) {
            let mut bad_buf = [0; BLOCK];
            bad_buf[0..DIGEST].copy_from_slice(Hash::compute(&badend).as_bytes());
            bad_buf[DIGEST..].copy_from_slice(&badend);
            assert_eq!(
                Block::new(&bad_buf).from_checkpoint(&checkpoint),
                Err(BlockError::Signature)
            );
        }

        // Make sure Block::from_hash_at_index() is getting called
        for bad_block_hash in HashBitFlipper::new(&checkpoint.block_hash) {
            let bad_checkpoint = CheckPoint::new(
                checkpoint.chain_hash,
                bad_block_hash,
                checkpoint.block_index,
            );
            assert_eq!(
                Block::new(&buf).from_checkpoint(&bad_checkpoint),
                Err(BlockError::BlockHash)
            );
        }
        for bad_index in U128BitFlipper::new(checkpoint.block_index) {
            let bad_checkpoint =
                CheckPoint::new(checkpoint.chain_hash, checkpoint.block_hash, bad_index);
            assert_eq!(
                Block::new(&buf).from_checkpoint(&bad_checkpoint),
                Err(BlockError::Index)
            );
        }

        // Test Block::from_checkpoint() specific error
        for bad_chain_hash in HashBitFlipper::new(&checkpoint.chain_hash) {
            let bad_checkpoint = CheckPoint::new(
                bad_chain_hash,
                checkpoint.block_hash,
                checkpoint.block_index,
            );
            assert_eq!(
                Block::new(&buf).from_checkpoint(&bad_checkpoint),
                Err(BlockError::ChainHash)
            );
        }

        // when index == 0
        let mut buf = [0; BLOCK];
        let seed = Seed::generate().unwrap();
        let payload = random_payload();
        let block_hash = sign_block(&mut buf, &seed, &payload, None);
        let state = Block::new(&buf).from_hash_at_index(&block_hash, 0).unwrap();
        let checkpoint = state.to_checkpoint();
        assert_eq!(checkpoint.block_index, 0);
        assert_eq!(checkpoint.block_hash, block_hash);
        assert_eq!(checkpoint.chain_hash, block_hash);
        assert_eq!(Block::new(&buf).from_checkpoint(&checkpoint), Ok(state));
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
            Hash::from_bytes([0; DIGEST]), // ZERO_HASH
            Hash::from_bytes([0; DIGEST]), // ZERO_HASH
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
            badbuf[0..DIGEST].copy_from_slice(Hash::compute(&badend).as_bytes());
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
        for bad_index in U128BitFlipper::new(0) {
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
        let seed = Seed::generate().unwrap();
        let mut block = MutBlock::new(&mut buf, &random_payload());
        block.sign(&seed);
        let chain_hash = block.finalize();
        let tail = Block::new(&buf).from_hash_at_index(&chain_hash, 0).unwrap();

        let seed = seed.advance().unwrap();
        let mut block = MutBlock::new(&mut buf, &random_payload());
        block.set_previous(&tail);
        block.sign(&seed);
        block.finalize();
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
        let seed = seed.advance().unwrap();
        let mut block = MutBlock::new(&mut buf, &random_payload());
        block.set_previous(&tail);
        block.sign(&seed);
        block.finalize();
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
        assert_eq!(
            Hash::compute(&buf),
            Hash::from_hex(
                "8fd910701a748a13e71c71ce72d7ee5768c2bdeb82ee42c788f223fad6b5086eefdd85ab998e8b5e"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_sign_block() {
        // Sign first block
        let mut buf = [69; BLOCK]; // 69 to make sure block gets zeroed first
        let seed = Seed::generate().unwrap();
        let payload = random_payload();
        let chain_hash = sign_block(&mut buf, &seed, &payload, None);

        // chain_hash and previous_hash are always zeros in 1st block:
        assert_eq!(&buf[0..DIGEST], chain_hash.as_bytes());
        assert_eq!(&buf[BLOCK - DIGEST * 2..], &[0; DIGEST * 2]);

        // Sign 2nd block
        let tail = Block::new(&buf).from_hash_at_index(&chain_hash, 0).unwrap();
        buf.fill(69);
        let seed = seed.advance().unwrap();
        let payload = random_payload();
        let block_hash = sign_block(&mut buf, &seed, &payload, Some(&tail));
        assert_ne!(chain_hash, block_hash);
        assert_eq!(&buf[0..DIGEST], block_hash.as_bytes());

        // chain_hash and previous_hash are always == in the 2nd block:
        assert_eq!(&buf[BLOCK - DIGEST..], chain_hash.as_bytes());
        assert_eq!(
            &buf[BLOCK - DIGEST * 2..BLOCK - DIGEST],
            chain_hash.as_bytes()
        );

        // Sign 3rd block
        let tail2 = Block::new(&buf).from_hash_at_index(&block_hash, 1).unwrap();
        buf.fill(69);
        let seed = seed.advance().unwrap();
        let payload = random_payload();
        let block2_hash = sign_block(&mut buf, &seed, &payload, Some(&tail2));
        assert_ne!(block_hash, block2_hash);
        assert_ne!(chain_hash, block2_hash);
        assert_eq!(&buf[0..DIGEST], block2_hash.as_bytes());
        assert_eq!(
            &buf[BLOCK - DIGEST * 2..BLOCK - DIGEST],
            chain_hash.as_bytes()
        );
        assert_eq!(&buf[BLOCK - DIGEST..], block_hash.as_bytes());
    }

    #[test]
    #[should_panic]
    fn test_sign_block_panic() {
        // Sign first block
        let mut buf = [0; BLOCK];
        let seed = Seed::generate().unwrap();
        let payload = random_payload();
        let chain_hash = sign_block(&mut buf, &seed, &payload, None);

        // Sign 2nd block, but double advance the seed:
        let tail = Block::new(&buf).from_hash_at_index(&chain_hash, 0).unwrap();
        let seed = seed.advance().unwrap().advance().unwrap();
        let payload = random_payload();
        let _block_hash = sign_block(&mut buf, &seed, &payload, Some(&tail));
    }
}
