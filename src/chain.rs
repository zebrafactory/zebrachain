//! Writes/reads blocks to/from non-volitile storage and network.

use crate::block::{Block, BlockError, BlockState};
use crate::tunable::*;
use std::fs::File;
use std::io;
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

pub struct Chain {
    file: File,
    buf: [u8; BLOCK],
    state: ChainState,
}

impl Chain {
    pub fn open(mut file: File) -> io::Result<Self> {
        let mut buf = [0; BLOCK];
        file.read_exact(&mut buf)?;
        if let Ok(state) = ChainState::open(&buf) {
            Ok(Self { file, buf, state })
        } else {
            Err(io::Error::other("first block is bad"))
        }
    }

    fn read_next(&mut self) -> io::Result<()> {
        self.file.read_exact(&mut self.buf)
    }

    pub fn open_and_validate(mut file: File) -> io::Result<Self> {
        let mut chain = Chain::open(file)?;
        while chain.read_next().is_ok() {}
        Ok(chain)
    }

    pub fn append(&mut self, buf: &[u8]) -> io::Result<&BlockState> {
        if self.state.append(buf).is_ok() {
            self.file.write_all(buf)?;
            Ok(&self.state.tail)
        } else {
            Err(io::Error::other("appended block is bad"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MutBlock;
    use crate::pksign::SecretSigner;
    use crate::secretseed::Seed;
    use crate::tunable::*;
    use blake3::Hash;
    use std::io::Seek;
    use tempfile::tempfile;

    fn dummy_block_state() -> BlockState {
        BlockState {
            counter: 0,
            block_hash: Hash::from_bytes([1; DIGEST]),
            chain_hash: Hash::from_bytes([2; DIGEST]),
            next_pubkey_hash: Hash::from_bytes([3; DIGEST]),
        }
    }

    fn dummy_chain_state() -> ChainState {
        ChainState {
            head: dummy_block_state(),
            tail: dummy_block_state(),
        }
    }

    fn new_valid_first_block() -> [u8; BLOCK] {
        let mut buf = [0; BLOCK];
        let seed = Seed::create(&[69; 32]);
        let secsign = SecretSigner::new(&seed);
        let state_hash = Hash::from_bytes([2; 32]);
        let mut block = MutBlock::new(&mut buf, &state_hash);
        secsign.sign(&mut block);
        block.finalize();
        buf
    }


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

    #[test]
    fn test_chain_open() {
        let mut file = tempfile().unwrap();
        assert!(Chain::open(file.try_clone().unwrap()).is_err());
        file.write_all(&[69; BLOCK]).unwrap();
        file.rewind().unwrap();
        assert!(Chain::open(file.try_clone().unwrap()).is_err());

        let mut file = tempfile().unwrap();
        file.write_all(&new_valid_first_block()).unwrap();
        file.rewind().unwrap();
        let chain = Chain::open(file).unwrap();
    }

    #[test]
    fn test_chain_read_next() {
        let mut file = tempfile().unwrap();
        let mut chain = Chain {
            file: file.try_clone().unwrap(),
            buf: [0; BLOCK],
            state: dummy_chain_state(),
        };
        assert!(chain.read_next().is_err());
        assert_eq!(chain.buf, [0; BLOCK]);
        file.write_all(&[69; BLOCK]).unwrap();
        file.rewind().unwrap();
        assert!(chain.read_next().is_ok());
        assert_eq!(chain.buf, [69; BLOCK]);
        assert!(chain.read_next().is_err());
        assert_eq!(chain.buf, [69; BLOCK]);
    }
}
