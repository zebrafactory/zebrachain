mod chain;
mod pksign;

use blake3::{hash, Hash};

const DIGEST: usize = 32;
const SIGNATURE: usize = 64; // Need more Dilithium, Captian!
const PUBKEY: usize = 32; // STILL need more Dilithium, Captian!!!

const PAYLOAD: usize = SIGNATURE + PUBKEY + DIGEST + DIGEST;
//                                          ^^^^^^ NEXT_PUBKKEY_HASH
//                                                   ^^^^^^ PREVIOUS_BLOCK_HASH

const HASHABLE: usize = PAYLOAD + DIGEST; // Ends with hash of previous block
const BLOCK: usize = DIGEST + HASHABLE; // Begins with hash of HASHABLE slice

/*
A full block looks like:

    HASH || PAYLOAD || PREVIOUS_HASH

Where:

    HASH = hash(PAYLOAD || PREVIOUS_HASH)

And PAYLOAD expands to:

    SIGNATURE || PUBKEY || NEXT_PUBKEY_HASH || STATE_HASH

Where:

    SIGNATURE = sign(PUBKEY || NEXT_PUBKEY_HASH || STATE_HASH || PREVIOUS_HASH)
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

    pub fn hash(&self) -> Hash {
        let bytes = self.buf[0..DIGEST].try_into().expect("whoa, that sucks");
        Hash::from_bytes(bytes)
    }

    fn as_hashable(&self) -> &[u8] {
        &self.buf[DIGEST..]
    }

    fn as_signable(&self) -> &[u8] {
        &self.buf[DIGEST + SIGNATURE..]
    }

    fn compute_hash(&self) -> Hash {
        hash(self.as_hashable())
    }

    fn hash_is_valid(&self) -> bool {
        self.compute_hash() == self.hash()
    }

    pub fn previous_hash(&self) -> Hash {
        let bytes = self.buf[BLOCK - DIGEST..]
            .try_into()
            .expect("whoa, that sucks");
        Hash::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED: &str = "e17e48f651b5d03585d26accca19bd39466a3aa46f7d499c4bd5a449eb2a0097";

    fn new_expected() -> Hash {
        Hash::from_hex(EXPECTED).unwrap()
    }

    fn new_valid_store() -> Vec<u8> {
        let mut store = Vec::with_capacity(BLOCK);
        store.extend_from_slice(new_expected().as_bytes());
        store.extend_from_slice(&[2; PAYLOAD][..]);
        store.extend_from_slice(&[3; DIGEST][..]);
        store
    }

    fn new_store() -> Vec<u8> {
        let mut store: Vec<u8> = Vec::with_capacity(BLOCK);
        store.extend_from_slice(&[1; DIGEST][..]);
        store.extend_from_slice(&[2; PAYLOAD][..]);
        store.extend_from_slice(&[3; DIGEST][..]);
        store
    }

    fn new_store2() -> Vec<u8> {
        let mut store: Vec<u8> = Vec::with_capacity(BLOCK);
        store.extend_from_slice(&[1; DIGEST][..]);
        store.extend_from_slice(&[2; SIGNATURE][..]);
        store.extend_from_slice(&[3; PUBKEY][..]);
        store.extend_from_slice(&[4; DIGEST][..]);  // NEXT_PUBKEY_HASH
        store.extend_from_slice(&[5; DIGEST][..]);  // STATE_HASH
        store.extend_from_slice(&[6; DIGEST][..]);  // PREVIOUS_HASH
        store
    }

    #[test]
    fn block_new() {
        let store: Vec<u8> = vec![0; BLOCK];
        let block = Block::new(&store[..]);
    }

    #[test]
    #[should_panic(expected = "Need a 224 byte slice; got 223 bytes")]
    fn block_new_short_panic() {
        let store: Vec<u8> = vec![0; BLOCK - 1];
        let block = Block::new(&store[..]);
    }

    #[test]
    #[should_panic(expected = "Need a 224 byte slice; got 225 bytes")]
    fn block_new_long_panic() {
        let store: Vec<u8> = vec![0; BLOCK + 1];
        let block = Block::new(&store[..]);
    }

    #[test]
    fn block_hash() {
        let store = new_store();
        let block = Block::new(&store[..]);
        let hash = block.hash();
        assert_eq!(hash, Hash::from_bytes([1; DIGEST]));
    }

    #[test]
    fn block_as_hashable() {
        let store = new_store();
        let block = Block::new(&store[..]);
        let mut expected = Vec::new();
        expected.extend_from_slice(&[2; PAYLOAD][..]);
        expected.extend_from_slice(&[3; DIGEST][..]);
        assert_eq!(block.as_hashable(), &expected[..]);
    }

    #[test]
    fn block_as_signable() {
        let store = new_store2();
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

    #[test]
    fn block_previous_hash() {
        let store = new_store();
        let block = Block::new(&store[..]);
        let hash = block.previous_hash();
        assert_eq!(hash, Hash::from_bytes([3; DIGEST]));
    }
}
