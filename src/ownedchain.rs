//! High level API for signing new blocks.
//!
//! An owned chain is one you have the secret seed state for, a chain you can generate new valid
//! blocks for.

use crate::always::*;
use crate::{
    BlockState, Chain, ChainStore, CheckPoint, Hash, MutOwnedBlock, OwnedBlockState, Payload,
    Secret, SecretBlockState, SecretChain, SecretChainHeader, SecretChainStore, Seed, sign_block,
};
use std::io;
use std::path::Path;

/// Used to create new blocks in a chain you own.
pub struct OwnedChainStore {
    store: ChainStore,
    secret_store: SecretChainStore,
}

impl OwnedChainStore {
    /// Create an OwnedChainStore.
    ///
    /// This has no side effects, performs no file system operations.
    pub fn new(store_dir: &Path, secret_store_dir: &Path) -> Self {
        let store = ChainStore::new(store_dir);
        let secret_store = SecretChainStore::new(secret_store_dir);
        Self {
            store,
            secret_store,
        }
    }

    /// Create a new owned chain, internally generating the entropy.
    pub fn generate_chain(&self, payload: &Payload, password: &[u8]) -> io::Result<OwnedChain> {
        let initial_entropy = match Secret::generate() {
            Ok(secret) => secret,
            Err(err) => return Err(err.to_io_error()),
        };
        self.create_chain(&initial_entropy, payload, password)
    }

    /// Create a new [OwnedChain].
    pub fn create_chain(
        &self,
        initial_entropy: &Secret,
        payload: &Payload,
        password: &[u8],
    ) -> io::Result<OwnedChain> {
        let mut buf = [0; BLOCK];
        let mut secret_buf = vec![0u8; SECRET_BLOCK_AEAD];
        let mut block = MutOwnedBlock::new(&mut buf, &mut secret_buf, payload);
        let seed = Seed::create(initial_entropy);
        block.sign(&seed);
        let chain_header =
            SecretChainHeader::create(initial_entropy.mix_with_context(CONTEXT_CHAIN_SALT));
        let (chain_hash, secret_block_hash, chain_secret) =
            block.finalize_first(&chain_header, password);
        let chain = self.store.create_chain(&buf, &chain_hash)?;
        let secret_chain = self.secret_store.create_chain(
            secret_buf,
            chain_header,
            chain_secret,
            &chain_hash,
            &secret_block_hash,
        )?;
        Ok(OwnedChain::new(chain, secret_chain))
    }

    /// Open and full validate both chain and secret chain.
    pub fn open_chain(&self, chain_hash: &Hash, password: &[u8]) -> io::Result<OwnedChain> {
        let chain = self.store.open_chain(chain_hash)?;
        let secret_chain = self.secret_store.open_chain(chain_hash, password)?;
        Ok(OwnedChain::new(chain, secret_chain))
    }

    /// Open and partially validate chain from a [CheckPoint] forward.
    ///
    /// FIXME: secret chains don't yet support resuming from a checkpoint, so
    /// the secret chain is always fully validated.
    pub fn resume_chain(&self, checkpoint: &CheckPoint, password: &[u8]) -> io::Result<OwnedChain> {
        let chain = self.store.resume_chain(checkpoint)?;
        let secret_chain = self
            .secret_store
            .open_chain(&checkpoint.chain_hash, password)?;
        Ok(OwnedChain::new(chain, secret_chain))
    }

    /// Reconstruct public chain from its secret chain.
    pub fn secret_to_public(&self, secret_chain: &SecretChain) -> io::Result<Chain> {
        let mut buf = [0; BLOCK];
        let mut iter = secret_chain.iter();
        let sec = iter.nth(0).unwrap()?;
        let chain_hash = sign_block(&mut buf, &sec.seed, &sec.payload, None);
        let mut chain = self.store.create_chain(&buf, &chain_hash)?;
        let mut tail = chain.head().clone();
        for result in iter {
            let sec = result?;
            sign_block(&mut buf, &sec.seed, &sec.payload, Some(&tail));
            tail = chain.append(&buf)?.clone();
            assert_eq!(tail.block_hash, sec.public_block_hash);
        }
        Ok(chain)
    }

    /// Reference to the underlying [ChainStore].
    pub fn store(&self) -> &ChainStore {
        &self.store
    }

    /// Reference to the underlying [SecretChainStore].
    pub fn secret_store(&self) -> &SecretChainStore {
        &self.secret_store
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
    /// Construct an owned chain.
    pub fn new(chain: Chain, secret_chain: SecretChain) -> Self {
        Self {
            chain,
            secret_chain,
        }
    }

    /// Sign next block, internally generating new entropy.
    pub fn sign(&mut self, payload: &Payload) -> io::Result<&BlockState> {
        let new_entropy = match Secret::generate() {
            Ok(secret) => secret,
            Err(err) => return Err(err.to_io_error()),
        };
        self.sign_raw(&new_entropy, payload)
    }

    /// Sign next block.
    pub fn sign_raw(&mut self, new_entropy: &Secret, payload: &Payload) -> io::Result<&BlockState> {
        let seed = self.secret_chain.advance(new_entropy);
        let obs = self.state();
        let mut buf = [0; BLOCK];
        let chain_secret = self.secret_chain.chain_secret.clone();
        let mut block = MutOwnedBlock::new(&mut buf, self.secret_chain.as_mut_buf(), payload);
        block.set_previous(&obs);
        block.sign(&seed);
        let (block_hash, secret_block_hash) = block.finalize(&chain_secret);
        self.secret_chain.append(&secret_block_hash)?;
        assert_eq!(self.secret_chain.tail().block_hash, secret_block_hash);
        let result = self.chain.append(&buf)?;
        assert_eq!(result.block_hash, block_hash);
        Ok(result)
    }

    /// Number of blocks in this owned chain.
    pub fn count(&self) -> u64 {
        self.chain.count()
    }

    /// [Chain.tail()].
    pub fn head(&self) -> &BlockState {
        self.chain.head()
    }

    /// [Chain.tail()].
    pub fn tail(&self) -> &BlockState {
        self.chain.tail()
    }

    /// [SecretChain.tail()].
    pub fn secret_tail(&self) -> &SecretBlockState {
        self.secret_chain.tail()
    }

    /// Chain hash.
    pub fn chain_hash(&self) -> &Hash {
        self.chain.chain_hash()
    }

    /// Returns current [OwnedBlockState].
    pub fn state(&self) -> OwnedBlockState {
        OwnedBlockState::new(self.chain.tail().clone(), self.secret_chain.tail().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhelpers::random_payload;
    use tempfile;

    #[test]
    fn test_ownedchainstore() {
        let payload = random_payload();

        let tmpdir1 = tempfile::TempDir::new().unwrap();
        let tmpdir2 = tempfile::TempDir::new().unwrap();
        let ocs = OwnedChainStore::new(tmpdir1.path(), tmpdir2.path());

        let initial_entropy = Secret::generate().unwrap();
        let mut chain = ocs
            .create_chain(&initial_entropy, &payload, b"Bad Password")
            .unwrap();
        assert_eq!(chain.tail().block_index, 0);
        let chain_hash = chain.chain_hash().clone();
        for i in 1..=420 {
            let new_entropy = Secret::generate().unwrap();
            chain.sign_raw(&new_entropy, &random_payload()).unwrap();
            assert_eq!(chain.tail().block_index, i);
        }
        assert_eq!(chain.count(), 421);
        let tail = chain.tail().clone();
        let chain = ocs.open_chain(&chain_hash, b"Bad Password").unwrap();
        assert_eq!(chain.tail(), &tail);
        assert_eq!(chain.count(), 421);
    }

    #[test]
    fn test_ocs_build() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let ocs = OwnedChainStore::new(tmpdir.path(), tmpdir.path());
        let payload = random_payload();
        let initial_entropy = Secret::generate().unwrap();
        let oc = ocs
            .create_chain(&initial_entropy, &payload, b"Bad Password")
            .unwrap();
        let chain_hash = oc.chain_hash();
        let tail = oc.tail();
        let oc = ocs.open_chain(&chain_hash, b"Bad Password").unwrap();
        assert_eq!(oc.chain_hash(), chain_hash);
        assert_eq!(oc.tail(), tail);
    }

    #[test]
    fn test_ocs_secret_to_public() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let ocs = OwnedChainStore::new(tmpdir.path(), tmpdir.path());
        let payload = random_payload();
        let initial_entropy = Secret::generate().unwrap();
        let mut chain = ocs
            .create_chain(&initial_entropy, &payload, b"Bad Password")
            .unwrap();
        for _ in 0..420 {
            let new_entropy = Secret::generate().unwrap();
            chain.sign_raw(&new_entropy, &random_payload()).unwrap();
        }
        let tail = chain.tail().clone();
        ocs.store().remove_chain_file(&tail.chain_hash).unwrap();
        let secret_chain = ocs
            .secret_store
            .open_chain(&tail.chain_hash, b"Bad Password")
            .unwrap();
        let chain = ocs.secret_to_public(&secret_chain).unwrap();
        assert_eq!(chain.tail(), &tail);
    }
}
