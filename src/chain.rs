use crate::block::Block;
use crate::tunable::*;
use blake3::Hash;
use std::fs::File;
use std::io::Result as IoResult;
use std::io::{Read, Seek};

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

    fn validate(&mut self) -> IoResult<()> {
        self.file.rewind()?;
        self.file.read_exact(&mut self.buf)?;
        if let Ok(block) = Block::open(&self.buf) {
            let first_hash = block.first_hash();
            let mut previous_hash = block.hash();
            let mut next_pubkey_hash = block.next_pubkey_hash();
            while self.file.read_exact(&mut self.buf).is_ok() {
                if let Ok(block) = Block::from_previous(&self.buf, next_pubkey_hash, previous_hash)
                {
                    previous_hash = block.hash();
                    next_pubkey_hash = block.next_pubkey_hash();
                }
            }
        }
        Ok(())
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
