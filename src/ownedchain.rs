//! High level API for signing new blocks.
//!
//! An owned chain is one you have the secret seed state for, a chain you can generate new valid
//! blocks for.

use crate::always::*;
use crate::block::{BlockState, SigningRequest};
use crate::chain::{Chain, ChainStore, CheckPoint};
use crate::pksign::sign_block;
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
    pub fn new(chain_dir: &Path, secret_store: SecretChainStore) -> Self {
        Self {
            store: ChainStore::new(chain_dir),
            secret_store,
        }
    }

    pub fn store(&self) -> &ChainStore {
        &self.store
    }

    pub fn create_chain(&self, request: &SigningRequest) -> io::Result<OwnedChain> {
        let seed = Seed::auto_create().unwrap();
        let mut buf = [0; BLOCK];
        let chain_hash = sign_block(&mut buf, &seed, request, None);
        let chain = self.store.create_chain(&buf, &chain_hash)?;
        let secret_chain = self
            .secret_store
            .create_chain(&chain_hash, &seed, request)?;
        Ok(OwnedChain::new(seed, chain, secret_chain))
    }

    pub fn open_chain(&self, chain_hash: &Hash) -> io::Result<OwnedChain> {
        let chain = self.store.open_chain(chain_hash)?;
        let secret_chain = self.secret_store.open_chain(chain_hash)?;
        let seed = secret_chain.tail().seed();
        Ok(OwnedChain::new(seed, chain, secret_chain))
    }

    pub fn resume_chain(&self, checkpoint: &CheckPoint) -> io::Result<OwnedChain> {
        let chain = self.store.resume_chain(checkpoint)?;
        let secret_chain = self.secret_store.open_chain(&checkpoint.chain_hash)?;
        let seed = secret_chain.tail().seed();
        Ok(OwnedChain::new(seed, chain, secret_chain))
    }

    pub fn secret_to_public(&self, secret_chain: &SecretChain) -> io::Result<Chain> {
        let mut buf = [0; BLOCK];
        let mut iter = secret_chain.iter();
        let sec = iter.nth(0).unwrap()?;
        let chain_hash = sign_block(&mut buf, &sec.seed(), &sec.signing_request(), None);
        let mut chain = self.store.create_chain(&buf, &chain_hash)?;
        let mut tail = chain.head().clone();
        for result in iter {
            let sec = result?;
            sign_block(&mut buf, &sec.seed(), &sec.signing_request(), Some(&tail));
            tail = chain.append(&buf)?.clone();
        }
        Ok(chain)
    }
}

/// Sign new blocks in an owned chain.
pub struct OwnedChain {
    seed: Seed,
    chain: Chain,
    secret_chain: SecretChain,
}

impl OwnedChain {
    pub fn new(seed: Seed, chain: Chain, secret_chain: SecretChain) -> Self {
        Self {
            seed,
            chain,
            secret_chain,
        }
    }

    pub fn count(&self) -> u64 {
        self.chain.count()
    }

    pub fn sign_next(&mut self, request: &SigningRequest) -> io::Result<&BlockState> {
        let seed = self.seed.auto_advance().unwrap();
        let mut buf = [0; BLOCK];
        sign_block(&mut buf, &seed, request, Some(self.tail()));
        self.secret_chain.commit(&seed, request)?;
        let result = self.chain.append(&buf)?;
        self.seed.commit(seed);
        Ok(result)
    }

    pub fn head(&self) -> &BlockState {
        self.chain.head()
    }

    pub fn tail(&self) -> &BlockState {
        self.chain.tail()
    }

    pub fn chain_hash(&self) -> &Hash {
        self.chain.chain_hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secretseed::random_secret;
    use crate::testhelpers::random_request;
    use tempfile;

    #[test]
    fn test_ownedchainstore() {
        let request = random_request();

        let tmpdir1 = tempfile::TempDir::new().unwrap();
        let tmpdir2 = tempfile::TempDir::new().unwrap();
        let secstore = SecretChainStore::new(tmpdir2.path(), random_secret().unwrap());
        let ocs = OwnedChainStore::new(tmpdir1.path(), secstore);

        let mut chain = ocs.create_chain(&request).unwrap();
        assert_eq!(chain.tail().index, 0);
        let chain_hash = chain.chain_hash().clone();
        for i in 1..=420 {
            chain.sign_next(&random_request()).unwrap();
            assert_eq!(chain.tail().index, i);
        }
        let tail = chain.tail().clone();
        let chain = ocs.open_chain(&chain_hash).unwrap();
        assert_eq!(chain.tail(), &tail);
    }
}
