use crate::tunable::*;
use blake3::Hash;
use std::fs::File;
use std::io::Result as IoResult;

/*
For now we will fully validate all chains when opening them.

Validate first block
Check againts external first block hash
Walk chain till last block.

*/

pub struct Chain {
    pub first_hash: Hash,
    file: File,
    buf: [u8; BLOCK],
}

impl Chain {
    pub fn new(file: File) -> Self {
        let first_hash = Hash::from_bytes([0; DIGEST]);
        Self {
            first_hash,
            file,
            buf: [0; BLOCK],
        }
    }

    pub fn open(first_hash: Hash, file: File) -> IoResult<Self> {
        Ok(Self::new(file))
    }

    pub fn append(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile;

    #[test]
    fn test_chain_new() {
        let tmp = tempfile::tempfile().unwrap();
        let chain = Chain::new(tmp);
    }
}
