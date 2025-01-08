//! Read and write secret blocks in a chain.

use crate::always::*;
use crate::fsutil::{build_filename, create_for_append, open_for_append};
use crate::secretblock::{MutSecretBlock, SecretBlock};
use crate::secretseed::Seed;
use blake3::Hash;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

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
    tail: SecretBlock,
}

impl SecretChain {
    pub fn create(mut file: File, seed: Seed, state_hash: &Hash) -> io::Result<Self> {
        let mut buf = [0; SECRET_BLOCK];
        let mut block = MutSecretBlock::new(&mut buf);
        block.set_seed(&seed);
        block.set_state_hash(state_hash);
        let block = block.finalize();
        file.write_all(&buf)?;
        Ok(Self {
            file,
            seed,
            tail: block,
        })
    }

    pub fn open(mut file: File) -> io::Result<Self> {
        let mut buf = [0; SECRET_BLOCK];
        file.read_exact(&mut buf)?;
        let mut block = SecretBlock::open(&buf).unwrap();
        while file.read_exact(&mut buf).is_ok() {
            block = SecretBlock::from_previous(&buf, &block).unwrap();
        }
        let seed = block.get_seed();
        Ok(Self {
            file,
            seed,
            tail: block,
        })
    }

    pub fn current_seed(&self) -> Seed {
        self.seed.clone()
    }

    pub fn advance(&self, new_entropy: &[u8; 32]) -> Seed {
        self.seed.advance(new_entropy)
    }

    pub fn auto_advance(&self) -> Seed {
        self.seed.auto_advance()
    }

    pub fn commit(&mut self, seed: Seed, state_hash: &Hash) -> io::Result<()> {
        let mut buf = [0; SECRET_BLOCK];
        let mut block = MutSecretBlock::new(&mut buf);
        block.set_seed(&seed);
        block.set_state_hash(state_hash);
        block.set_previous(&self.tail);
        let block = block.finalize();
        self.file.write_all(&buf)?;
        self.seed.commit(seed);
        self.tail = block;
        Ok(())
    }

    pub fn into_file(self) -> File {
        self.file
    }
}

/// Organizes [SecretChain] files in a directory.
pub struct SecretChainStore {
    dir: PathBuf,
}

impl SecretChainStore {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    pub fn open_chain(&self, chain_hash: &Hash) -> io::Result<SecretChain> {
        let filename = build_filename(&self.dir, chain_hash);
        let file = open_for_append(&filename)?;
        SecretChain::open(file)
    }

    pub fn create_chain(
        &self,
        chain_hash: &Hash,
        seed: Seed,
        state_hash: &Hash,
    ) -> io::Result<SecretChain> {
        let filename = build_filename(&self.dir, chain_hash);
        let file = create_for_append(&filename)?;
        SecretChain::create(file, seed, state_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Seek;
    use tempfile::tempfile;

    #[test]
    fn test_chain_create() {
        let file = tempfile().unwrap();
        let seed = Seed::create(&[42; 32]);
        let state_hash = Hash::from_bytes([69; DIGEST]);
        let result = SecretChain::create(file, seed.clone(), &state_hash);
        assert!(result.is_ok());
        let mut file = result.unwrap().into_file();
        file.rewind().unwrap();
        let mut buf = [0; SECRET_BLOCK];
        file.read_exact(&mut buf).unwrap();
        let block = SecretBlock::open(&buf).unwrap();
        assert_eq!(seed, block.get_seed());
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
        SecretChain::open(file).unwrap();
    }

    #[test]
    fn test_chain_advance_and_commit() {
        let entropy = [69; 32];
        let file = tempfile().unwrap();
        let seed = Seed::create(&entropy);
        let state_hash = Hash::from_bytes([42; DIGEST]);
        let mut chain = SecretChain::create(file, seed, &state_hash).unwrap();
        for i in 0u8..=255 {
            let next = chain.advance(&entropy);
            let state_hash = Hash::from_bytes([i; DIGEST]);
            chain.commit(next, &state_hash).unwrap();
        }
        let mut file = chain.into_file();
        file.rewind().unwrap();
        SecretChain::open(file).unwrap();
    }

    #[test]
    #[should_panic(expected = "cannot commit out of sequence seed")]
    fn test_chain_commit_panic() {
        let entropy = &[69; 32];
        let file = tempfile().unwrap();
        let seed = Seed::create(&entropy);
        let state_hash = Hash::from_bytes([42; DIGEST]);
        let mut chain = SecretChain::create(file, seed, &state_hash).unwrap();
        let next = chain.advance(&entropy);
        let next_next = next.advance(&entropy);
        chain.commit(next_next, &state_hash).unwrap();
    }
}
