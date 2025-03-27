//! High level API for signing new blocks.
//!
//! An owned chain is one you have the secret seed state for, a chain you can generate new valid
//! blocks for.
//!
//! FIXME: As signing cannot fail (shouldn't fail anyway), we don' want calls to getrandom::fill(),
//! which can fail, to be inside calls to the top-level signing method.

use crate::always::*;
use crate::block::{BlockState, SigningRequest};
use crate::chain::{Chain, ChainStore, CheckPoint};
use crate::ownedblock::{OwnedBlockState, sign};
use crate::pksign::sign_block;
use crate::secretchain::{SecretChain, SecretChainStore};
use crate::secretseed::{Secret, Seed};
use blake3::Hash;
use std::io;
use std::path::Path;

pub struct OwnedChainStore {
    store: ChainStore,
    secret_store: SecretChainStore,
}

impl OwnedChainStore {
    pub fn new(store: ChainStore, secret_store: SecretChainStore) -> Self {
        Self {
            store,
            secret_store,
        }
    }

    pub fn build(store_dir: &Path, secret_store_dir: &Path, secret: Secret) -> Self {
        let store = ChainStore::new(store_dir);
        let secret_store = SecretChainStore::new(secret_store_dir, secret);
        Self::new(store, secret_store)
    }

    pub fn store(&self) -> &ChainStore {
        &self.store
    }

    pub fn secret_store(&self) -> &SecretChainStore {
        &self.secret_store
    }

    pub fn create_chain(
        &self,
        initial_entropy: &Hash,
        request: &SigningRequest,
    ) -> io::Result<OwnedChain> {
        let seed = Seed::create(initial_entropy);
        let mut buf = [0; BLOCK];
        let mut secbuf: Vec<u8> = vec![0; SECRET_BLOCK_AEAD];
        secbuf.resize(SECRET_BLOCK, 0);
        let (chain_hash, _) = sign(&seed, request, &mut buf, &mut secbuf[0..SECRET_BLOCK], None);
        let chain = self.store.create_chain(&buf, &chain_hash)?;
        let secret_chain = self.secret_store.create_chain2(&chain_hash, secbuf)?;
        Ok(OwnedChain::new(chain, secret_chain))
    }

    pub fn open_chain(&self, chain_hash: &Hash) -> io::Result<OwnedChain> {
        let chain = self.store.open_chain(chain_hash)?;
        let secret_chain = self.secret_store.open_chain(chain_hash)?;
        Ok(OwnedChain::new(chain, secret_chain))
    }

    pub fn resume_chain(&self, checkpoint: &CheckPoint) -> io::Result<OwnedChain> {
        let chain = self.store.resume_chain(checkpoint)?;
        let secret_chain = self.secret_store.open_chain(&checkpoint.chain_hash)?;
        Ok(OwnedChain::new(chain, secret_chain))
    }

    pub fn secret_to_public(&self, secret_chain: &SecretChain) -> io::Result<Chain> {
        let mut buf = [0; BLOCK];
        let mut iter = secret_chain.iter();
        let sec = iter.nth(0).unwrap()?;
        let chain_hash = sign_block(&mut buf, &sec.seed, &sec.request, None);
        let mut chain = self.store.create_chain(&buf, &chain_hash)?;
        let mut tail = chain.head().clone();
        for result in iter {
            let sec = result?;
            sign_block(&mut buf, &sec.seed, &sec.request, Some(&tail));
            tail = chain.append(&buf)?.clone();
        }
        Ok(chain)
    }
}

/// Sign new blocks in an owned chain.
///
/// An [OwnedChain] wraps a [Chain] and a [SecretChain] together. New blocks are signed using the
/// [Seed] state from the [SecretChain], and then the new block is appended to the [Chain].
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

    pub fn sign(
        &mut self,
        new_entropy: &Hash,
        request: &SigningRequest,
    ) -> io::Result<&BlockState> {
        let seed = self.secret_chain.advance(new_entropy);
        let obs = self.state();
        let mut buf = [0; BLOCK];
        let (block_hash, secret_block_hash) = sign(
            &seed,
            request,
            &mut buf,
            self.secret_chain.as_mut_buf(),
            Some(obs),
        );
        self.secret_chain.commit(&seed, request)?;
        assert_eq!(self.secret_chain.tail().block_hash, secret_block_hash);
        let result = self.chain.append(&buf)?;
        assert_eq!(result.block_hash, block_hash);
        Ok(result)
    }

    pub fn count(&self) -> u64 {
        self.chain.count()
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

    pub fn state(&self) -> OwnedBlockState {
        OwnedBlockState::new(self.chain.tail().clone(), self.secret_chain.tail().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secretseed::generate_secret;
    use crate::testhelpers::random_request;
    use tempfile;

    #[test]
    fn test_ownedchainstore() {
        let request = random_request();

        let tmpdir1 = tempfile::TempDir::new().unwrap();
        let tmpdir2 = tempfile::TempDir::new().unwrap();
        let store = ChainStore::new(tmpdir1.path());
        let secstore = SecretChainStore::new(tmpdir2.path(), generate_secret().unwrap());
        let ocs = OwnedChainStore::new(store, secstore);

        let initial_entropy = generate_secret().unwrap();
        let mut chain = ocs.create_chain(&initial_entropy, &request).unwrap();
        assert_eq!(chain.tail().index, 0);
        let chain_hash = chain.chain_hash().clone();
        for i in 1..=420 {
            let new_entropy = generate_secret().unwrap();
            chain.sign(&new_entropy, &random_request()).unwrap();
            assert_eq!(chain.tail().index, i);
        }
        assert_eq!(chain.count(), 421);
        let tail = chain.tail().clone();
        let chain = ocs.open_chain(&chain_hash).unwrap();
        assert_eq!(chain.tail(), &tail);
        assert_eq!(chain.count(), 421);
    }

    #[test]
    fn test_ocs_build() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let secret = generate_secret().unwrap();
        let ocs = OwnedChainStore::build(tmpdir.path(), tmpdir.path(), secret);
        let request = random_request();
        let initial_entropy = generate_secret().unwrap();
        let oc = ocs.create_chain(&initial_entropy, &request).unwrap();
        let chain_hash = oc.chain_hash();
        let tail = oc.tail();
        let oc = ocs.open_chain(&chain_hash).unwrap();
        assert_eq!(oc.chain_hash(), chain_hash);
        assert_eq!(oc.tail(), tail);
    }

    #[test]
    fn test_ocs_secret_to_public() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let secret = generate_secret().unwrap();
        let ocs = OwnedChainStore::build(tmpdir.path(), tmpdir.path(), secret);
        let request = random_request();
        let initial_entropy = generate_secret().unwrap();
        let mut chain = ocs.create_chain(&initial_entropy, &request).unwrap();
        for _ in 0..420 {
            let new_entropy = generate_secret().unwrap();
            chain.sign(&new_entropy, &random_request()).unwrap();
        }
        let tail = chain.tail().clone();
        ocs.store().remove_chain_file(&tail.chain_hash).unwrap();
        let secret_chain = ocs.secret_store.open_chain(&tail.chain_hash).unwrap();
        let chain = ocs.secret_to_public(&secret_chain).unwrap();
        assert_eq!(chain.tail(), &tail);
    }
}
