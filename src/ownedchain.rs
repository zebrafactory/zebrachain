//! High level API for signing new blocks.
//!
//! An owned chain is one you p

use crate::always::*;
use crate::block::BlockState;
use crate::chain::{Chain, ChainStore};
use crate::pksign::{create_first_block, create_next_block};
use crate::secretchain::{SecretChain, SecretChainStore};
use crate::secretseed::Seed;
use blake3::Hash;
use std::io;
use std::path::Path;

pub struct OwnedChainStore {
    store: ChainStore,
    secret_store: SecretChainStore,
}

impl OwnedChainStore {
    pub fn new(chain_dir: &Path, secret_chain_dir: &Path) -> Self {
        Self {
            store: ChainStore::new(chain_dir),
            secret_store: SecretChainStore::new(secret_chain_dir),
        }
    }

    pub fn create_owned_chain(&self, state_hash: &Hash) -> io::Result<OwnedChain> {
        let seed = Seed::auto_create();
        let mut buf = [0; BLOCK];
        let block = create_first_block(&mut buf, &seed, state_hash);
        let chain = self.store.create_chain(&block)?;
        let chain_hash = block.hash();
        let secret_chain = self
            .secret_store
            .create_chain(&chain_hash, seed, state_hash)?;
        Ok(OwnedChain::new(chain, secret_chain))
    }
}

/// Sign new blocks in an owned chain.
pub struct OwnedChain {
    chain: Chain,
    secret_chain: SecretChain,
}

impl OwnedChain {
    pub fn new(chain: Chain, secret_chain: SecretChain) -> Self {
        Self {
            chain,
            secret_chain,
        }
    }

    pub fn sign_next(&mut self, state_hash: &Hash) -> io::Result<&BlockState> {
        let seed = self.secret_chain.auto_advance();
        let state = &self.chain.state.tail;
        let mut buf = [0; BLOCK];
        create_next_block(&mut buf, &seed, state_hash, state);
        let ret = self.chain.append(&buf);
        self.secret_chain.commit(seed, state_hash)?;
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
    fn test_ownedchainstore() {
        let tmpdir1 = tempfile::TempDir::new().unwrap();
        let tmpdir2 = tempfile::TempDir::new().unwrap();
        let ocs = OwnedChainStore::new(tmpdir1.path(), tmpdir2.path());
        let chainsigner = ocs.create_owned_chain(&random_hash()).unwrap();
    }
}
