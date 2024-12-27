//! Read and write secret blocks in a chain.

use crate::secretblock::{MutSecretBlock, SecretBlock, SecretBlockInfo};
use crate::secretseed::Seed;
use crate::tunable::*;
use std::fs::File;
use std::io::Result as IoResult;
use std::io::{Read, Seek, SeekFrom, Write};

/// Save secret chain to non-volitile storage.
///
/// This is pure crap currently.  We need validation and encryption of this.
///
/// But remember an import use case for ZebraChain is Hardware Security Modules
/// that *never* write any secrets to non-volitle storage.  Always on, only in
/// memory.
///
/// Good idea: when we are saving a secret chain, we should include the
/// state_hash and timestamp in the secret block... that way the public block
/// can be recreating from the secret chain if the public block doesn't make it
/// to non-volitile storage.
pub struct SecretChain {
    file: File,
    seed: Seed,
    tail: SecretBlockInfo,
}

impl SecretChain {
    pub fn create(mut file: File, seed: Seed) -> IoResult<Self> {
        let mut buf = [0; SECRET_BLOCK];
        let mut block = MutSecretBlock::new(&mut buf);
        block.set_seed(&seed);
        let block_hash = block.finalize();
        let block = SecretBlock::from_hash(&buf, &block_hash).unwrap();
        file.write_all(&buf)?;
        Ok(Self {
            file,
            seed,
            tail: block.info,
        })
    }

    pub fn open(mut file: File) -> IoResult<Self> {
        let mut buf = [0; SECRET_BLOCK];
        file.read_exact(&mut buf)?;
        let mut info = SecretBlock::open(&buf).unwrap().info;
        while file.read_exact(&mut buf).is_ok() {
            info = SecretBlock::from_previous(&buf, &info).unwrap().info;
        }
        let seed = info.get_seed();
        Ok(Self {
            file,
            seed,
            tail: info,
        })
    }

    pub fn current_seed(&self) -> Seed {
        self.seed.clone()
    }

    pub fn advance(&self, new_entropy: &[u8; 32]) -> Seed {
        self.seed.advance(new_entropy)
    }

    pub fn commit(&mut self, seed: Seed) -> IoResult<()> {
        let mut buf = [0; SECRET_BLOCK];
        let mut block = MutSecretBlock::new(&mut buf);
        block.set_seed(&seed);
        block.set_previous_hash(&self.tail.block_hash);
        let block_hash = block.finalize();
        self.file.write_all(&buf)?;
        self.seed.commit(seed);
        self.tail = SecretBlock::from_hash(&buf, &block_hash).unwrap().info;
        Ok(())
    }

    pub fn into_file(self) -> File {
        self.file
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secretblock::SecretBlockError;
    use blake3::hash;
    use std::collections::HashSet;
    use tempfile::tempfile;

    #[test]
    fn test_chain_create() {
        let file = tempfile().unwrap();
        let seed = Seed::create(&[42; 32]);
        let result = SecretChain::create(file, seed.clone());
        assert!(result.is_ok());
        let mut file = result.unwrap().into_file();
        file.rewind().unwrap();
        let mut buf = [0; SECRET_BLOCK];
        file.read_exact(&mut buf).unwrap();
        let info = SecretBlock::open(&buf).unwrap().info;
        assert_eq!(seed, info.get_seed());
    }

    #[test]
    fn test_chain_open() {
        let mut file = tempfile().unwrap();
        assert!(SecretChain::open(file.try_clone().unwrap()).is_err());
        let mut buf = [0; SECRET_BLOCK];
        let mut block = MutSecretBlock::new(&mut buf);
        let seed = Seed::create(&[69; 32]);
        block.set_seed(&seed);
        block.finalize();
        file.write_all(&buf).unwrap();
        file.rewind().unwrap();
        let chain = SecretChain::open(file).unwrap();
    }

    #[test]
    fn test_chain_advance_and_commit() {
        let entropy = [69; 32];
        let mut file = tempfile().unwrap();
        let seed = Seed::create(&entropy);
        let mut chain = SecretChain::create(file, seed).unwrap();
        for i in 0u8..=255 {
            let next = chain.advance(&entropy);
            chain.commit(next).unwrap();
        }
        let mut file = chain.into_file();
        file.rewind().unwrap();
        let chain = SecretChain::open(file).unwrap();
    }

    #[test]
    #[should_panic(expected = "cannot commit out of sequence seed")]
    fn test_chain_commit_panic() {
        let entropy = &[69; 32];
        let file = tempfile().unwrap();
        let seed = Seed::create(&entropy);
        let mut chain = SecretChain::create(file, seed).unwrap();
        let next = chain.advance(&entropy);
        let next_next = next.advance(&entropy);
        chain.commit(next_next);
    }
}
