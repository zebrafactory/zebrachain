use blake3::Hash;


const DIGEST: usize = 32;

const PAYLOAD: usize = 69;  // Haha, for now.

const SIGNABLE: usize = PAYLOAD + DIGEST;  // Ends with hash of previous block

const BLOCK: usize = DIGEST + SIGNABLE;


/*
HASH | PAYLOAD | PREVIOUS
*/

struct Block<'a> {
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
        let bytes: [u8; DIGEST] = self.buf[0..DIGEST]
            .try_into().expect("whoa, that sucks");
        Hash::from_bytes(bytes)
    }

    pub fn previous_hash(&self) -> Hash {
        let bytes: [u8; DIGEST] = self.buf[BLOCK - DIGEST..]
            .try_into().expect("whoa, that sucks");
        Hash::from_bytes(bytes)
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    fn new_store() -> Vec<u8> {
        let mut store: Vec<u8> = Vec::with_capacity(BLOCK);
        store.extend_from_slice(&[1; DIGEST][..]);
        store.extend_from_slice(&[2; PAYLOAD][..]);
        store.extend_from_slice(&[3; DIGEST][..]);
        store
    }

    #[test]
    fn block_new() {
        let store: Vec<u8> = vec![0; BLOCK];
        let block = Block::new(&store[..]);
    }

    #[test]
    #[should_panic (expected="Need a 133 byte slice; got 132 bytes")]
    fn block_new_panic_short() {
        let store: Vec<u8> = vec![0; BLOCK - 1];
        let block = Block::new(&store[..]);
    }

    #[test]
    #[should_panic (expected="Need a 133 byte slice; got 134 bytes")]
    fn block_new_panic_long() {
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
    fn block_previous_hash() {
        let store = new_store();
        let block = Block::new(&store[..]);
        let hash = block.previous_hash();
        assert_eq!(hash, Hash::from_bytes([3; DIGEST]));
    }
}

