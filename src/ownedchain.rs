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
    secret_store: Option<SecretChainStore>,
}

impl OwnedChainStore {
    pub fn new(chain_dir: &Path, secret_chain_dir: Option<&Path>) -> Self {
        Self {
            store: ChainStore::new(chain_dir),
            secret_store: secret_chain_dir.map(SecretChainStore::new),
        }
    }

    pub fn store(&self) -> &ChainStore {
        &self.store
    }

    fn create_secret_chain(
        &self,
        seed: &Seed,
        chain_hash: &Hash,
        request: &SigningRequest,
    ) -> io::Result<Option<SecretChain>> {
        if let Some(secret_store) = self.secret_store.as_ref() {
            Ok(Some(secret_store.create_chain(chain_hash, seed, request)?))
        } else {
            Ok(None)
        }
    }

    fn open_secret_chain(&self, chain_hash: &Hash) -> io::Result<Option<SecretChain>> {
        if let Some(secret_store) = self.secret_store.as_ref() {
            Ok(Some(secret_store.open_chain(chain_hash)?))
        } else {
            Ok(None)
        }
    }

    pub fn create_chain(&self, request: &SigningRequest) -> io::Result<OwnedChain> {
        let seed = Seed::auto_create().unwrap();
        let mut buf = [0; BLOCK];
        let chain_hash = sign_block(&mut buf, &seed, request, None);
        let chain = self.store.create_chain(&buf, &chain_hash)?;
        let secret_chain = self.create_secret_chain(&seed, &chain_hash, request)?;
        Ok(OwnedChain::new(seed, chain, secret_chain))
    }

    pub fn open_chain(&self, chain_hash: &Hash) -> io::Result<OwnedChain> {
        let chain = self.store.open_chain(chain_hash)?;
        if let Some(secret_chain) = self.open_secret_chain(chain_hash)? {
            let seed = secret_chain.tail().seed();
            Ok(OwnedChain::new(seed, chain, Some(secret_chain)))
        } else {
            Err(io::Error::other(format!(
                "No secret chain for {}",
                chain_hash
            )))
        }
    }

    pub fn resume_chain(&self, checkpoint: &CheckPoint) -> io::Result<OwnedChain> {
        let chain = self.store.resume_chain(checkpoint)?;
        if let Some(secret_chain) = self.open_secret_chain(&checkpoint.chain_hash)? {
            let seed = secret_chain.tail().seed();
            Ok(OwnedChain::new(seed, chain, Some(secret_chain)))
        } else {
            Err(io::Error::other(format!(
                "No secret chain for {}",
                checkpoint.chain_hash
            )))
        }
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

    pub fn count(&self) -> u64 {
        self.chain.count()
    }

    pub fn sign_next(&mut self, request: &SigningRequest) -> io::Result<&BlockState> {
        let seed = self.seed.auto_advance().unwrap();
        let mut buf = [0; BLOCK];
        sign_block(&mut buf, &seed, request, Some(self.tail()));
        if let Some(secret_chain) = self.secret_chain.as_mut() {
            secret_chain.commit(&seed, request)?;
        }
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
    use crate::testhelpers::random_request;
    use tempfile;

    #[test]
    fn test_ownedchainstore() {
        let request = random_request();

        let tmpdir1 = tempfile::TempDir::new().unwrap();
        let tmpdir2 = tempfile::TempDir::new().unwrap();

        // Paths do not exist:
        let nope1 = tmpdir1.path().join("nope1");
        let nope2 = tmpdir2.path().join("nope2");

        let ocs = OwnedChainStore::new(&nope1, None);
        assert!(ocs.secret_store.is_none());
        assert!(ocs.create_chain(&request).is_err());

        let ocs = OwnedChainStore::new(&nope1, Some(&nope2));
        assert!(ocs.secret_store.is_some());
        assert!(ocs.create_chain(&request).is_err());

        // Paths are directories:
        let ocs = OwnedChainStore::new(tmpdir1.path(), None);
        assert!(ocs.secret_store.is_none());
        let mut chain = ocs.create_chain(&request).unwrap();
        assert_eq!(chain.tail().index, 0);
        let chain_hash = chain.chain_hash().clone();
        for i in 1..=420 {
            chain.sign_next(&random_request()).unwrap();
            assert_eq!(chain.tail().index, i);
        }
        assert!(ocs.open_chain(&chain_hash).is_err()); // No secret chain store

        let ocs = OwnedChainStore::new(tmpdir1.path(), Some(tmpdir2.path()));
        assert!(ocs.secret_store.is_some());
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
