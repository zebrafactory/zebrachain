//! High level API for signing new blocks.
//!
//! An owned chain is one you p

use crate::always::*;
use crate::block::BlockState;
use crate::chain::{Chain, ChainStore};
use crate::pksign::{sign_first_block, sign_next_block};
use crate::secretchain::{SecretChain, SecretChainStore};
use crate::secretseed::Seed;
use blake3::Hash;
use std::io;
use std::path::Path;

pub struct OwnedChainStore {
    store: ChainStore,
    secret_store: Option<SecretChainStore>,
}

impl OwnedChainStore {
    pub fn new(chain_dir: &Path, secret_chain_dir: Option<&Path>) -> Self {
        Self {
            store: ChainStore::new(chain_dir),
            secret_store: secret_chain_dir.map(SecretChainStore::new),
        }
    }

    fn create_secret_chain(
        &self,
        seed: &Seed,
        chain_hash: &Hash,
        state_hash: &Hash,
    ) -> io::Result<Option<SecretChain>> {
        if let Some(secret_store) = self.secret_store.as_ref() {
            Ok(Some(
                secret_store.create_chain(chain_hash, seed, state_hash)?,
            ))
        } else {
            Ok(None)
        }
    }

    pub fn create_owned_chain(&self, state_hash: &Hash) -> io::Result<OwnedChain> {
        let seed = Seed::auto_create();
        let mut buf = [0; BLOCK];
        let chain_hash = sign_first_block(&mut buf, &seed, state_hash);
        let chain = self.store.create_chain2(&buf, &chain_hash)?;
        let secret_chain = self.create_secret_chain(&seed, &chain_hash, state_hash)?;
        Ok(OwnedChain::new(seed, chain, secret_chain))
    }
}

/// Sign new blocks in an owned chain.
pub struct OwnedChain {
    seed: Seed,
    chain: Chain,
    secret_chain: Option<SecretChain>,
}

impl OwnedChain {
    pub fn new(seed: Seed, chain: Chain, secret_chain: Option<SecretChain>) -> Self {
        Self {
            seed,
            chain,
            secret_chain,
        }
    }

    pub fn sign_next(&mut self, state_hash: &Hash) -> io::Result<&BlockState> {
        let seed = self.seed.auto_advance();
        let mut buf = [0; BLOCK];
        sign_next_block(&mut buf, &seed, state_hash, self.tail());
        if let Some(secret_chain) = self.secret_chain.as_mut() {
            secret_chain.commit(&seed, state_hash)?;
        }
        let ret = self.chain.append(&buf)?;
        self.seed.commit(seed);
        Ok(ret)
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
        let ocs = OwnedChainStore::new(tmpdir1.path(), Some(tmpdir2.path()));
        let _chainsigner = ocs.create_owned_chain(&random_hash()).unwrap();
    }
}
