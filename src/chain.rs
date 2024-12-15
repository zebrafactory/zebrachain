use crate::block::{Block, BlockError};
use blake3::Hash;

/*
For now we will fully validate all chains when opening them.

Validate first block
Check againts external first block hash
Walk chain till last block.

*/

pub struct ChainState {
    counter: u128,
    chain_hash: Hash,
    hash: Hash,
    next_pubkey_hash: Hash,
}

impl ChainState {
    pub fn open(buf: &[u8]) -> Result<Self, BlockError> {
        let block = Block::open(buf)?;
        Ok(Self {
            counter: 0,
            chain_hash: block.hash(),
            hash: block.hash(),
            next_pubkey_hash: block.next_pubkey_hash(),
        })
    }

    pub fn append(self, buf: &[u8]) -> Result<Self, BlockError> {
        let block = Block::from_previous(buf, self.next_pubkey_hash, self.hash)?;
        if block.chain_hash() != self.chain_hash {
            Err(BlockError::ChainHash)
        } else {
            Ok(Self {
                counter: self.counter + 1,
                chain_hash: self.chain_hash,
                hash: block.hash(),
                next_pubkey_hash: block.next_pubkey_hash(),
            })
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
            block.finalize().unwrap();
        }
        let block = Block::open(&buf).unwrap();
        let chain = ChainState::open(&buf).unwrap();
        assert_eq!(chain.counter, 0);
        assert_eq!(chain.chain_hash, block.hash());
        assert_eq!(chain.hash, block.hash());
        assert_eq!(chain.next_pubkey_hash, block.next_pubkey_hash());
    }
}
