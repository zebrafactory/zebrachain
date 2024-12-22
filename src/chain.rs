//! Writes/reads blocks to/from non-volitile storage and network.

use crate::block::{Block, BlockError, BlockState};
use crate::tunable::*;
use blake3::Hash;
use std::fs::File;
use std::io::Error as IoError;
use std::io::Result as IoResult;
use std::io::{Read, Write};

/*
For now we will fully validate all chains when opening them.

Validate first block
Check againts external first block hash
Walk chain till last block.

*/

pub struct ChainState {
    head: BlockState,
    tail: BlockState,
}

impl ChainState {
    pub fn open(buf: &[u8]) -> Result<Self, BlockError> {
        let block = Block::open(buf)?;
        Ok(Self {
            head: block.state(),
            tail: block.state(),
        })
    }

    pub fn append(&mut self, buf: &[u8]) -> Result<(), BlockError> {
        let block = Block::from_previous(buf, &self.tail)?;
        self.tail = block.state();
        assert_eq!(self.tail.chain_hash, self.head.chain_hash);
        Ok(())
    }
}

struct Chain {
    file: File,
    buf: [u8; BLOCK],
    state: ChainState,
}

impl Chain {
    pub fn open(mut file: File) -> IoResult<Self> {
        let mut buf = [0; BLOCK];
        file.read_exact(&mut buf)?;
        if let Ok(state) = ChainState::open(&buf) {
            Ok(Self { file, buf, state })
        } else {
            Err(IoError::other("first block is bad"))
        }
    }

    pub fn read_next(&mut self) -> IoResult<()> {
        self.file.read_exact(&mut self.buf)?;
        Ok(())
    }

    pub fn open_and_validate(mut file: File) -> IoResult<Self> {
        let mut chain = Chain::open(file)?;
        while chain.read_next().is_ok() && chain.state.append(&chain.buf).is_ok() {}
        Ok(chain)
    }

    pub fn append(&mut self, buf: &[u8]) -> IoResult<&BlockState> {
        if self.state.append(buf).is_ok() {
            self.file.write_all(buf)?;
            Ok(&self.state.tail)
        } else {
            Err(IoError::other("appended block is bad"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MutBlock;
    use crate::pksign::SecretSigner;
    use crate::secrets::Seed;
    use crate::tunable::*;
    use tempfile;

    #[test]
    fn test_chainstate_open() {
        let mut buf = [0; BLOCK];
        assert!(ChainState::open(&buf).is_err());
        {
            let seed = Seed::create(&[69; 32]);
            let signer = SecretSigner::new(&seed);
            let state_hash = Hash::from_bytes([42; 32]);
            let mut block = MutBlock::new(&mut buf, &state_hash);
            signer.sign(&mut block);
            block.finalize();
        }
        let block = Block::open(&buf).unwrap();
        let chain = ChainState::open(&buf).unwrap();
        assert_eq!(chain.tail.counter, 0);
        assert_eq!(chain.tail.chain_hash, block.chain_hash());
        assert_eq!(chain.tail.block_hash, block.hash());
        assert_eq!(chain.tail.next_pubkey_hash, block.next_pubkey_hash());
    }
}
