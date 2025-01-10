//! Writes/reads blocks to/from non-volitile storage and network.

use crate::always::*;
use crate::block::{Block, BlockState};
use crate::fsutil::{build_filename, create_for_append, open_for_append};
use blake3::Hash;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/*
For now we will fully validate all chains when opening them.

Validate first block
Check againt external first block hash
Walk chain till last block.
*/

/// Read and write blocks to a file.
pub struct Chain {
    buf: [u8; BLOCK],
    file: File,
    pub head: BlockState,
    pub tail: BlockState,
}

impl Chain {
    pub fn open_unknown(mut file: File) -> io::Result<Self> {
        let mut buf = [0; BLOCK];
        file.read_exact(&mut buf)?;
        match Block::open(&buf) {
            Ok(block) => Ok(Self {
                file,
                buf,
                head: block.state(),
                tail: block.state(),
            }),
            Err(err) => Err(err.to_io_error()),
        }
    }

    pub fn open(mut file: File, chain_hash: &Hash) -> io::Result<Self> {
        let mut buf = [0; BLOCK];
        file.read_exact(&mut buf)?;
        match Block::from_hash(&buf, chain_hash) {
            Ok(block) => Ok(Self {
                file,
                buf,
                head: block.state(),
                tail: block.state(),
            }),
            Err(err) => Err(err.to_io_error()),
        }
    }

    pub fn create(mut file: File, buf: &[u8], chain_hash: &Hash) -> io::Result<Self> {
        match Block::from_hash(buf, chain_hash) {
            Ok(block) => {
                file.write_all(buf)?;
                let buf = [0; BLOCK];
                Ok(Self {
                    file,
                    buf,
                    head: block.state(),
                    tail: block.state(),
                })
            }
            Err(err) => Err(err.to_io_error()),
        }
    }

    fn read_next(&mut self) -> io::Result<()> {
        self.file.read_exact(&mut self.buf)
    }

    pub fn validate(&mut self) -> io::Result<()> {
        while self.read_next().is_ok() {
            match Block::from_previous(&self.buf, &self.tail) {
                Ok(block) => {
                    self.tail = block.state();
                }
                Err(err) => {
                    return Err(err.to_io_error());
                }
            }
        }
        Ok(())
    }

    pub fn append(&mut self, buf: &[u8]) -> io::Result<&BlockState> {
        match Block::from_previous(buf, &self.tail) {
            Ok(block) => {
                self.file.write_all(buf)?;
                self.tail = block.state();
                Ok(&self.tail)
            }
            Err(err) => Err(err.to_io_error()),
        }
    }

    pub fn into_file(self) -> File {
        self.file
    }
}

/// Organizes [Chain] files in a directory.
pub struct ChainStore {
    dir: PathBuf,
}

impl ChainStore {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    fn chain_filename(&self, chain_hash: &Hash) -> PathBuf {
        build_filename(&self.dir, chain_hash)
    }

    pub fn open_chain_file(&self, chain_hash: &Hash) -> io::Result<File> {
        let filename = self.chain_filename(chain_hash);
        open_for_append(&filename)
    }

    pub fn create_chain_file(&self, chain_hash: &Hash) -> io::Result<File> {
        let filename = self.chain_filename(chain_hash);
        create_for_append(&filename)
    }

    pub fn open_chain(&self, chain_hash: &Hash) -> io::Result<Chain> {
        let file = self.open_chain_file(chain_hash)?;
        Chain::open(file, chain_hash)
    }

    pub fn create_chain2(&self, buf: &[u8], chain_hash: &Hash) -> io::Result<Chain> {
        let file = self.create_chain_file(chain_hash)?;
        Chain::create(file, buf, chain_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MutBlock;
    use crate::pksign::SecretSigner;
    use crate::secretseed::{random_hash, Seed};
    use crate::testhelpers::BitFlipper;
    use blake3::Hash;
    use std::io::Seek;
    use tempfile;

    fn dummy_block_state() -> BlockState {
        BlockState {
            counter: 0,
            block_hash: Hash::from_bytes([1; DIGEST]),
            chain_hash: Hash::from_bytes([2; DIGEST]),
            next_pubkey_hash: Hash::from_bytes([3; DIGEST]),
        }
    }

    fn new_valid_first_block() -> [u8; BLOCK] {
        let mut buf = [0; BLOCK];
        let seed = Seed::create(&[69; 32]);
        let secsign = SecretSigner::new(&seed);
        let state_hash = Hash::from_bytes([2; 32]);
        let mut block = MutBlock::new(&mut buf, &state_hash);
        secsign.sign(&mut block);
        block.finalize();
        buf
    }

    #[test]
    fn test_chain_open_unknown() {
        let mut file = tempfile::tempfile().unwrap();
        assert!(Chain::open_unknown(file.try_clone().unwrap()).is_err());
        file.write_all(&[69; BLOCK]).unwrap();
        file.rewind().unwrap();
        assert!(Chain::open_unknown(file.try_clone().unwrap()).is_err());

        let mut file = tempfile::tempfile().unwrap();
        let good = new_valid_first_block();
        file.write_all(&good).unwrap();
        file.rewind().unwrap();
        let mut chain = Chain::open_unknown(file).unwrap();
        assert!(chain.validate().is_ok());

        for bad in BitFlipper::new(&good) {
            let mut file = tempfile::tempfile().unwrap();
            file.write_all(&bad).unwrap();
            file.rewind().unwrap();
            assert!(Chain::open_unknown(file).is_err());
        }
    }

    #[test]
    fn test_chain_read_next() {
        let mut file = tempfile::tempfile().unwrap();
        let mut chain = Chain {
            file: file.try_clone().unwrap(),
            buf: [0; BLOCK],
            head: dummy_block_state(),
            tail: dummy_block_state(),
        };
        assert!(chain.read_next().is_err());
        assert_eq!(chain.buf, [0; BLOCK]);
        file.write_all(&[69; BLOCK]).unwrap();
        file.rewind().unwrap();
        assert!(chain.read_next().is_ok());
        assert_eq!(chain.buf, [69; BLOCK]);
        assert!(chain.read_next().is_err());
        assert_eq!(chain.buf, [69; BLOCK]);
    }

    #[test]
    fn test_chainstore_chain_filename() {
        let dir = PathBuf::from("/tmp/stuff/junk");
        let chainstore = ChainStore::new(&dir);
        let chain_hash = Hash::from_bytes([42; 32]);
        assert_eq!(
            chainstore.chain_filename(&chain_hash),
            PathBuf::from(
                "/tmp/stuff/junk/2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
            )
        );
    }

    #[test]
    fn test_chainstore_open_chain_file() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let chainstore = ChainStore::new(tmpdir.path());
        let chain_hash = random_hash();
        assert!(chainstore.open_chain_file(&chain_hash).is_err()); // File does not exist yet

        let filename = chainstore.chain_filename(&chain_hash);
        create_for_append(&filename).unwrap();
        assert!(chainstore.open_chain_file(&chain_hash).is_ok());
    }

    #[test]
    fn test_chainstore_create_chain_file() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let chainstore = ChainStore::new(tmpdir.path());
        let chain_hash = random_hash();
        assert!(chainstore.create_chain_file(&chain_hash).is_ok());
        assert!(chainstore.create_chain_file(&chain_hash).is_err()); // File already exists
    }

    #[test]
    fn test_chainstore_open_chain() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let chainstore = ChainStore::new(tmpdir.path());
        let chain_hash = random_hash();
        assert!(chainstore.open_chain(&chain_hash).is_err());
    }
}
