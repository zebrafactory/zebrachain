use crate::block::{Block, BlockError};
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
    counter: u128,
    first_hash: Hash,
    hash: Hash,
    next_pubkey_hash: Hash,
    state_hash: Hash,
}

impl Chain {
    pub fn open(buf: &[u8]) -> Result<Self, BlockError> {
        let block = Block::open(buf)?;
        Ok(Self {
            counter: 0,
            first_hash: block.hash(),
            hash: block.hash(),
            next_pubkey_hash: block.next_pubkey_hash(),
            state_hash: block.state_hash(),
        })
    }

    pub fn append(self, buf: &[u8]) -> Result<Self, BlockError> {
        let block = Block::from_previous(buf, self.next_pubkey_hash, self.hash)?;
        if block.first_hash() != self.first_hash {
            Err(BlockError::FirstHash)
        } else {
            Ok(Self {
                counter: self.counter + 1,
                first_hash: self.first_hash,
                hash: block.hash(),
                next_pubkey_hash: block.next_pubkey_hash(),
                state_hash: block.state_hash(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile;
    use crate::secrets::Seed;
    use crate::block::MutBlock;
    use crate::pksign::SecretSigner;

    #[test]
    fn test_chain_open() {
        let mut buf = [0; BLOCK];
        assert!(Chain::open(&buf).is_err());
        {
            let seed = Seed::create(&[69; 32]);
            let signer = SecretSigner::new(&seed);
            let state_hash = Hash::from_bytes([42; 32]);
            let mut block = MutBlock::new(&mut buf, &state_hash);
            signer.sign(&mut block);
            block.finalize().unwrap();
        }
        let block = Block::open(&buf).unwrap();
        let chain = Chain::open(&buf).unwrap();
        assert_eq!(chain.counter, 0);
        assert_eq!(chain.first_hash, block.hash());
        assert_eq!(chain.hash, block.hash());
        assert_eq!(chain.next_pubkey_hash, block.next_pubkey_hash());
        assert_eq!(chain.state_hash, Hash::from_bytes([42; 32]));
    }
}
