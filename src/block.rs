use blake3::{hash, Hash};
use std::ops::Range;

const DIGEST: usize = 32;
const SIGNATURE: usize = 64; // Need more Dilithium, Captian!
const PUBKEY: usize = 32; // STILL need more Dilithium, Captian!!!
const BLOCK: usize = DIGEST * 4 + SIGNATURE + PUBKEY;

const HASHABLE_RANGE: Range<usize> = DIGEST..BLOCK;
const SIGNABLE_RANGE: Range<usize> = DIGEST + SIGNATURE..BLOCK;

const HASH_RANGE: Range<usize> = 0..DIGEST;
const SIGNATURE_RANGE: Range<usize> = DIGEST..DIGEST + SIGNATURE;
const PUBKEY_RANGE: Range<usize> = DIGEST + SIGNATURE..DIGEST + SIGNATURE + PUBKEY;
const NEXT_PUBKEY_HASH_RANGE: Range<usize> = BLOCK - DIGEST * 3..BLOCK - DIGEST * 2;
const STATE_HASH_RANGE: Range<usize> = BLOCK - DIGEST * 2..BLOCK - DIGEST;
const PREVIOUS_HASH_RANGE: Range<usize> = BLOCK - DIGEST..BLOCK;

/*
A Block has 6 fields (currently):

    HASH || SIGNATURE || PUBKEY || NEXT_PUBKEY_HASH || STATE_HASH || PREVIOUS_HASH

Where:

    HASH = hash(SIGNATURE || PUBKEY || NEXT_PUBKEY_HASH || STATE_HASH || PREVIOUS_HASH)

And where:

    SIGNATURE = sign(PUBKEY || NEXT_PUBKEY_HASH || STATE_HASH || PREVIOUS_HASH)

A COUNTER and TIMESTAMP will likely be added.
*/

pub struct Block<'a> {
    buf: &'a [u8],
}

impl<'a> Block<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        if buf.len() != BLOCK {
            panic!("Need a {BLOCK} byte slice; got {} bytes", buf.len());
        }
        Self { buf }
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

    fn hash_is_valid(&self) -> bool {
        self.compute_hash() == self.hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED: &str = "8c055bbd86ce68355dbccdea130317563c638f482690eb7fac3f821e624061fc";

    fn new_expected() -> Hash {
        Hash::from_hex(EXPECTED).unwrap()
    }

    fn extend_with_hashes(store: &mut Vec<u8>) {
        store.extend_from_slice(&[4; DIGEST][..]); // NEXT_PUBKEY_HASH
        store.extend_from_slice(&[5; DIGEST][..]); // STATE_HASH
        store.extend_from_slice(&[6; DIGEST][..]); // PREVIOUS_HASH
    }

    fn new_valid_store() -> Vec<u8> {
        let mut store = Vec::with_capacity(BLOCK);
        store.extend_from_slice(new_expected().as_bytes());
        store.extend_from_slice(&[2; SIGNATURE][..]);
        store.extend_from_slice(&[3; PUBKEY][..]);
        extend_with_hashes(&mut store);
        store
    }

    fn new_store() -> Vec<u8> {
        let mut store: Vec<u8> = Vec::with_capacity(BLOCK);
        store.extend_from_slice(&[1; DIGEST][..]);
        store.extend_from_slice(&[2; SIGNATURE][..]);
        store.extend_from_slice(&[3; PUBKEY][..]);
        extend_with_hashes(&mut store);
        store
    }

    #[test]
    fn test_ranges() {
        assert_eq!(HASHABLE_RANGE, 32..224);
        assert_eq!(SIGNABLE_RANGE, 96..224);

        assert_eq!(HASH_RANGE, 0..32);
        assert_eq!(SIGNATURE_RANGE, 32..96);
        assert_eq!(PUBKEY_RANGE, 96..128);
        assert_eq!(NEXT_PUBKEY_HASH_RANGE, 128..160);
        assert_eq!(STATE_HASH_RANGE, 160..192);
        assert_eq!(PREVIOUS_HASH_RANGE, 192..224);
    }

    #[test]
    fn block_new() {
        let store: Vec<u8> = vec![0; BLOCK];
        let _block = Block::new(&store[..]);
    }

    #[test]
    #[should_panic(expected = "Need a 224 byte slice; got 223 bytes")]
    fn block_new_short_panic() {
        let store: Vec<u8> = vec![0; BLOCK - 1];
        let _block = Block::new(&store[..]);
    }

    #[test]
    #[should_panic(expected = "Need a 224 byte slice; got 225 bytes")]
    fn block_new_long_panic() {
        let store: Vec<u8> = vec![0; BLOCK + 1];
        let _block = Block::new(&store[..]);
    }

    #[test]
    fn test_block_as_fns() {
        let store = new_store();
        let block = Block::new(&store[..]);
        assert_eq!(block.as_hash(), [1; DIGEST]);
        assert_eq!(block.as_signature(), [2; SIGNATURE]);
        assert_eq!(block.as_pubkey(), [3; PUBKEY]);
        assert_eq!(block.as_next_pubkey_hash(), [4; DIGEST]);
        assert_eq!(block.as_state_hash(), [5; DIGEST]);
        assert_eq!(block.as_previous_hash(), [6; DIGEST]);
    }

    #[test]
    fn test_block_hash_accessors() {
        let store = new_store();
        let block = Block::new(&store[..]);
        assert_eq!(block.hash(), Hash::from_bytes([1; DIGEST]));
        assert_eq!(block.next_pubkey_hash(), Hash::from_bytes([4; DIGEST]));
        assert_eq!(block.state_hash(), Hash::from_bytes([5; DIGEST]));
        assert_eq!(block.previous_hash(), Hash::from_bytes([6; DIGEST]));
    }

    #[test]
    fn block_as_hashable() {
        let store = new_store();
        let block = Block::new(&store[..]);
        assert_eq!(block.as_hashable(), &store[DIGEST..]);
    }

    #[test]
    fn block_as_signable() {
        let store = new_store();
        let block = Block::new(&store[..]);
        assert_eq!(block.as_signable(), &store[DIGEST + SIGNATURE..]);
    }

    #[test]
    fn block_compute_hash() {
        let store = new_store();
        let block = Block::new(&store[..]);
        let hash = block.compute_hash();
        assert_eq!(hash, new_expected());
    }

    #[test]
    fn block_hash_is_valid() {
        let store = new_store();
        let block = Block::new(&store[..]);
        assert!(!block.hash_is_valid());
        assert_ne!(block.hash(), new_expected());

        let store = new_valid_store();
        let block = Block::new(&store[..]);
        assert!(block.hash_is_valid());
        assert_eq!(block.hash(), new_expected());
    }
}
