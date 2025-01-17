//! High level API for signing new blocks.
//!
//! An owned chain is one you have the secret seed state for, a chain you can generate new valid
//! blocks for.

use crate::always::*;
use crate::block::{BlockState, SigningRequest};
use crate::chain::{Chain, ChainStore};
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

    pub fn create_owned_chain(&self, request: &SigningRequest) -> io::Result<OwnedChain> {
        let seed = Seed::auto_create();
        let mut buf = [0; BLOCK];
        let chain_hash = sign_block(&mut buf, &seed, request, None);
        let chain = self.store.create_chain(&buf, &chain_hash)?;
        let secret_chain = self.create_secret_chain(&seed, &chain_hash, request)?;
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

    pub fn sign_next(&mut self, signing_request: &SigningRequest) -> io::Result<&BlockState> {
        let seed = self.seed.auto_advance();
        let mut buf = [0; BLOCK];
        sign_block(&mut buf, &seed, signing_request, Some(self.tail()));
        if let Some(secret_chain) = self.secret_chain.as_mut() {
            secret_chain.commit(&seed, signing_request)?;
        }
        let ret = self.chain.append(&buf)?;
        self.seed.commit(seed);
        Ok(ret)
    }

    pub fn head(&self) -> &BlockState {
        self.chain.head()
    }

    pub fn tail(&self) -> &BlockState {
        self.chain.tail()
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
        let req = SigningRequest::new(random_hash(), random_hash());
        let _chain = ocs.create_owned_chain(&req).unwrap();
    }
}
