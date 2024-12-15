use crate::block::{Block, BlockError, BlockState};
use blake3::Hash;

/*
For now we will fully validate all chains when opening them.

Validate first block
Check againts external first block hash
Walk chain till last block.

*/

pub struct ChainState {
    tail: BlockState,
}

impl ChainState {
    pub fn open(buf: &[u8]) -> Result<Self, BlockError> {
        let block = Block::open(buf)?;
        Ok(Self {
            tail: block.state(),
        })
    }

    /*
        pub fn append(self, buf: &[u8]) -> Result<Self, BlockError> {
            let block = Block::from_previous(buf, self.next_pubkey_hash, self.hash)?;
            }
        }
    */
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
        assert_eq!(chain.tail.counter, 0);
        assert_eq!(chain.tail.chain_hash, block.chain_hash());
        assert_eq!(chain.tail.block_hash, block.hash());
        assert_eq!(chain.tail.next_pubkey_hash, block.next_pubkey_hash());
    }
}
