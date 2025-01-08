//! High level API for signing new blocks.
//!
//! An owned chain is one you p

use crate::always::*;
use crate::chain::{Chain, ChainStore};
use crate::pksign::create_first_block;
use crate::secretseed::Seed;
use blake3::Hash;
use std::io;

struct SignerMajig {
    store: ChainStore,
}

impl SignerMajig {
    pub fn new(store: ChainStore) -> Self {
        Self { store }
    }

    fn create_chain_signer(&self, state_hash: &Hash) -> io::Result<OwnedChain> {
        let seed = Seed::auto_create();
        let mut buf = [0; BLOCK];
        let block = create_first_block(&mut buf, &seed, state_hash);
        let chain = self.store.create_chain(&block)?;
        Ok(OwnedChain::new(chain, seed))
    }
}

/// Sign new blocks in an owned chain.
struct OwnedChain {
    chain: Chain,
    seed: Seed,
}

impl OwnedChain {
    pub fn new(chain: Chain, seed: Seed) -> Self {
        Self { chain, seed }
    }

    pub fn sign_next(&mut self, state_hash: &Hash) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secretseed::random_hash;
    use tempfile;

    #[test]
    fn test_signermajig() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let cs = ChainStore::new(tmpdir.path().to_path_buf());
        let smajig = SignerMajig::new(cs);
        let chainsigner = smajig.create_chain_signer(&random_hash()).unwrap();
    }
}
