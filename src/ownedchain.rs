//! High level API for signing new blocks.
//!
//! An owned chain is one you p

use crate::always::*;
use crate::block::BlockState;
use crate::chain::{Chain, ChainStore};
use crate::pksign::{create_first_block, create_next_block};
use crate::secretseed::Seed;
use blake3::Hash;
use std::io;
use std::path::Path;

pub struct OwnedChainStore {
    store: ChainStore,
}

impl OwnedChainStore {
    pub fn new(dir: &Path) -> Self {
        Self {
            store: ChainStore::new(dir),
        }
    }

    pub fn create_owned_chain(&self, state_hash: &Hash) -> io::Result<OwnedChain> {
        let seed = Seed::auto_create();
        let mut buf = [0; BLOCK];
        let block = create_first_block(&mut buf, &seed, state_hash);
        let chain = self.store.create_chain(&block)?;
        Ok(OwnedChain::new(chain, seed))
    }
}

/// Sign new blocks in an owned chain.
pub struct OwnedChain {
    chain: Chain,
    seed: Seed,
}

impl OwnedChain {
    pub fn new(chain: Chain, seed: Seed) -> Self {
        Self { chain, seed }
    }

    pub fn sign_next(&mut self, state_hash: &Hash) -> io::Result<&BlockState> {
        let seed = self.seed.auto_advance();
        let state = &self.chain.state.tail;
        let mut buf = [0; BLOCK];
        create_next_block(&mut buf, &seed, state_hash, state);
        let ret = self.chain.append(&buf);
        self.seed.commit(seed);
        ret
    }

    pub fn tail(&self) -> &BlockState {
        &self.chain.state.tail
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secretseed::random_hash;
    use tempfile;

    #[test]
    fn test_signermajig() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let smajig = OwnedChainStore::new(tmpdir.path());
        let chainsigner = smajig.create_owned_chain(&random_hash()).unwrap();
    }
}
