use crate::pksign::{verify_signature, KeyPair};
use crate::tunable::*;
use blake3::{hash, Hash};

#[derive(Debug, PartialEq)]
pub enum BlockError {
    /// Hash of block content does not match hash in block.
    Content,

    /// Public key is invalid or signature does not match.
    Signature,

    /// Block hash does not match expected external value.
    Hash,

    /// Public Key hash does not match expected external value.
    PubKeyHash,

    /// Previous hash does not match expected external value.
    PreviousHash,
}

pub type BlockResult<'a> = Result<Block<'a>, BlockError>;

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

    pub fn from_previous(buf: &'a [u8], pubkey_h: Hash, previous_h: Hash) -> BlockResult<'a> {
        let block = Block::open(buf)?;
        if block.compute_pubkey_hash() != pubkey_h {
            Err(BlockError::PubKeyHash)
        } else if block.previous_hash() != previous_h {
            Err(BlockError::PreviousHash)
        } else {
            Ok(block)
        }
    }

    fn as_hashable(&self) -> &[u8] {
        &self.buf[HASHABLE_RANGE]
    }

    fn as_signable(&self) -> &[u8] {
        &self.buf[SIGNABLE_RANGE]
    }

    fn as_hash(&self) -> &[u8] {
        &self.buf[HASH_RANGE]
    }

    fn as_signature(&self) -> &[u8] {
        &self.buf[SIGNATURE_RANGE]
    }

    fn as_pubkey(&self) -> &[u8] {
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
        verify_signature(self.buf)
    }
}

pub fn write_block(
    buf: &mut [u8],
    keypair: KeyPair,
    next_pubkey_hash: Hash,
    state_hash: Hash,
    previous_hash: Hash,
) {
    // Copy in these 3 hash fields:
    buf[NEXT_PUBKEY_HASH_RANGE].copy_from_slice(next_pubkey_hash.as_bytes());
    buf[STATE_HASH_RANGE].copy_from_slice(state_hash.as_bytes());
    buf[PREVIOUS_HASH_RANGE].copy_from_slice(previous_hash.as_bytes());

    // KeyPair.sign() will write public key and then signature:
    keypair.sign(buf);

    // Compute hash, copy value into hash field:
    let block_hash = hash(&buf[HASHABLE_RANGE]);
    buf[HASH_RANGE].copy_from_slice(block_hash.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::misc::BitFlipper;

    const EXPECTED: &str = "1235a30e9a3086fa131087c5683eeaa5e4733dfa28fe610d4ed2b76e114011c7";

    fn new_expected() -> Hash {
        Hash::from_hex(EXPECTED).unwrap()
    }

    fn new_valid_block() -> Vec<u8> {
        let mut buf = vec![0; BLOCK];
        let secret = [69; 32];
        let keypair = KeyPair::new(&secret);
        let next_pubkey_hash = Hash::from_bytes([1; 32]);
        let state_hash = Hash::from_bytes([2; 32]);
        let previous_hash = Hash::from_bytes([3; 32]);
        write_block(
            &mut buf[..],
            keypair,
            next_pubkey_hash,
            state_hash,
            previous_hash,
        );
        buf
    }

    fn new_dummy_block() -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::with_capacity(BLOCK);
        buf.extend_from_slice(&[1; DIGEST][..]);
        buf.extend_from_slice(&[2; SIGNATURE][..]);
        buf.extend_from_slice(&[3; PUBKEY][..]);
        buf.extend_from_slice(&[4; DIGEST][..]); // NEXT_PUBKEY_HASH
        buf.extend_from_slice(&[5; DIGEST][..]); // STATE_HASH
        buf.extend_from_slice(&[6; DIGEST][..]); // PREVIOUS_HASH
        buf.extend_from_slice(&[7; DIGEST][..]); // FIRST_HASH
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
        let next_pubkey_hash = block.compute_pubkey_hash();
        let previous_hash = block.previous_hash();
        assert!(Block::from_previous(&buf[..], next_pubkey_hash, previous_hash).is_ok());

        for bad in BitFlipper::new(next_pubkey_hash.as_bytes()) {
            let bytes: [u8; 32] = bad[..].try_into().unwrap();
            let h = Hash::from_bytes(bytes);
            assert_eq!(
                Block::from_previous(&buf[..], h, previous_hash),
                Err(BlockError::PubKeyHash)
            );
        }

        for bad in BitFlipper::new(previous_hash.as_bytes()) {
            let bytes: [u8; 32] = bad[..].try_into().unwrap();
            let h = Hash::from_bytes(bytes);
            assert_eq!(
                Block::from_previous(&buf[..], next_pubkey_hash, h),
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
    }

    #[test]
    fn test_block_hash_accessors() {
        let buf = new_dummy_block();
        let block = Block::new(&buf[..]);
        assert_eq!(block.hash(), Hash::from_bytes([1; DIGEST]));
        assert_eq!(block.next_pubkey_hash(), Hash::from_bytes([4; DIGEST]));
        assert_eq!(block.state_hash(), Hash::from_bytes([5; DIGEST]));
        assert_eq!(block.previous_hash(), Hash::from_bytes([6; DIGEST]));
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
}
