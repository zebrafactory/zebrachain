//! Read and write secret blocks in a chain.

use crate::always::*;
use crate::block::SigningRequest;
use crate::fsutil::{build_filename, create_for_append, open_for_append};
use crate::secretblock::{MutSecretBlock, SecretBlock};
use crate::secretseed::Seed;
use blake3::Hash;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

/// Save secret chain to non-volitile storage.
///
/// The SecretBlock and SecretChain are decent now, but we still aren't encrypting this. So still
/// kinda crappy.
///
/// But remember an import use case for ZebraChain is Hardware Security Modules that *never* write
/// any secrets to non-volitle storage.  Always on, only in memory.
pub struct SecretChain {
    file: File,
    tail: SecretBlock,
    count: u64,
}

impl SecretChain {
    pub fn create(mut file: File, seed: &Seed, request: &SigningRequest) -> io::Result<Self> {
        let mut buf = [0; SECRET_BLOCK];
        let mut block = MutSecretBlock::new(&mut buf);
        block.set_seed(seed);
        block.set_request(&request);
        let block = block.finalize();
        file.write_all(&buf)?;
        Ok(Self {
            file,
            tail: block,
            count: 1,
        })
    }

    pub fn open(mut file: File) -> io::Result<Self> {
        let mut buf = [0; SECRET_BLOCK];
        file.read_exact(&mut buf)?;
        let mut tail = match SecretBlock::open(&buf) {
            Ok(block) => block,
            Err(err) => return Err(err.to_io_error()),
        };
        let mut count = 1;
        while file.read_exact(&mut buf).is_ok() {
            tail = match SecretBlock::from_previous(&buf, &tail) {
                Ok(block) => block,
                Err(err) => return Err(err.to_io_error()),
            };
            count += 1;
        }
        Ok(Self { file, tail, count })
    }

    fn read_block(&self, buf: &mut [u8], index: u64) -> io::Result<()> {
        let offset = index * SECRET_BLOCK as u64;
        self.file.read_exact_at(buf, offset)
    }

    pub fn tail(&self) -> &SecretBlock {
        &self.tail
    }

    pub fn commit(&mut self, seed: &Seed, request: &SigningRequest) -> io::Result<()> {
        let mut buf = [0; SECRET_BLOCK];
        let mut block = MutSecretBlock::new(&mut buf);
        block.set_seed(seed);
        block.set_request(&request);
        block.set_previous(&self.tail);
        let block = block.finalize();
        self.file.write_all(&buf)?;
        self.tail = block;
        self.count += 1;
        Ok(())
    }

    pub fn into_file(self) -> File {
        self.file
    }

    pub fn iter(&self) -> SecretChainIter {
        SecretChainIter::new(self, self.count)
    }
}

impl<'a> IntoIterator for &'a SecretChain {
    type Item = io::Result<SecretBlock>;
    type IntoIter = SecretChainIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct SecretChainIter<'a> {
    secretchain: &'a SecretChain,
    index: u64,
    count: u64,
    tail: Option<SecretBlock>,
}

impl<'a> SecretChainIter<'a> {
    pub fn new(secretchain: &'a SecretChain, count: u64) -> Self {
        if count == 0 {
            panic!("count cannot be 0");
        }
        Self {
            secretchain,
            index: 0,
            count,
            tail: None,
        }
    }

    fn next_inner(&mut self) -> io::Result<SecretBlock> {
        assert!(self.index < self.count);
        let mut buf = [0; SECRET_BLOCK];
        self.secretchain.read_block(&mut buf, self.index)?;
        self.index += 1;

        let result = if let Some(tail) = self.tail.as_ref() {
            SecretBlock::from_previous(&buf, tail)
        } else {
            SecretBlock::open(&buf)
        };

        match result {
            Ok(block) => {
                self.tail = Some(block.clone());
                Ok(block)
            }
            Err(err) => Err(err.to_io_error()),
        }
    }
}

impl Iterator for SecretChainIter<'_> {
    type Item = io::Result<SecretBlock>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.count {
            Some(self.next_inner())
        } else {
            None
        }
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
        seed: &Seed,
        request: &SigningRequest,
    ) -> io::Result<SecretChain> {
        let filename = build_filename(&self.dir, chain_hash);
        let file = create_for_append(&filename)?;
        SecretChain::create(file, seed, request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secretseed::random_hash;
    use std::io::Seek;
    use tempfile::tempfile;

    #[test]
    fn test_chain_create() {
        let file = tempfile().unwrap();
        let seed = Seed::create(&[42; 32]);
        let request = SigningRequest::new(random_hash(), Hash::from_bytes([69; DIGEST]));
        let result = SecretChain::create(file, &seed, &request);
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
        let mut seed = Seed::create(&entropy);
        let request = SigningRequest::new(
            Hash::from_bytes([69; DIGEST]),
            Hash::from_bytes([42; DIGEST]),
        );
        let mut chain = SecretChain::create(file, &seed, &request).unwrap();
        assert_eq!(chain.count, 1);
        for i in 0u8..=255 {
            let next = seed.advance(&entropy);
            let request = SigningRequest::new(random_hash(), Hash::from_bytes([i; DIGEST]));
            chain.commit(&next, &request).unwrap();
            assert_eq!(chain.count, i as u64 + 2);
            seed.commit(next);
        }
        let mut file = chain.into_file();
        file.rewind().unwrap();
        SecretChain::open(file).unwrap();
    }
}
