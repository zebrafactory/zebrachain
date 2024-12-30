//! Writes/reads blocks to/from non-volitile storage and network.

use crate::always::*;
use crate::block::{Block, BlockError, BlockState};
use blake3::Hash;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/*
For now we will fully validate all chains when opening them.

Validate first block
Check againts external first block hash
Walk chain till last block.

*/

pub struct ChainState {
    pub head: BlockState,
    pub tail: BlockState,
}

impl ChainState {
    pub fn open(buf: &[u8]) -> Result<Self, BlockError> {
        let block = Block::open(buf)?;
        Ok(Self {
            head: block.state(),
            tail: block.state(),
        })
    }

    pub fn append(&mut self, buf: &[u8]) -> Result<(), BlockError> {
        let block = Block::from_previous(buf, &self.tail)?;
        self.tail = block.state();
        assert_eq!(self.tail.chain_hash, self.head.block_hash);
        Ok(())
    }
}

pub struct Chain {
    file: File,
    buf: [u8; BLOCK],
    pub state: ChainState,
}

impl Chain {
    pub fn open(mut file: File) -> io::Result<Self> {
        let mut buf = [0; BLOCK];
        file.read_exact(&mut buf)?;
        if let Ok(state) = ChainState::open(&buf) {
            Ok(Self { file, buf, state })
        } else {
            Err(io::Error::other("first block is bad"))
        }
    }

    fn read_next(&mut self) -> io::Result<()> {
        self.file.read_exact(&mut self.buf)
    }

    pub fn validate(&mut self) -> io::Result<()> {
        while self.read_next().is_ok() {
            if self.state.append(&self.buf).is_err() {
                return Err(io::Error::other("block is bad"));
            }
        }
        Ok(())
    }

    pub fn append(&mut self, buf: &[u8]) -> io::Result<&BlockState> {
        if self.state.append(buf).is_ok() {
            self.file.write_all(buf)?;
            Ok(&self.state.tail)
        } else {
            Err(io::Error::other("appended block is bad"))
        }
    }

    pub fn into_file(self) -> File {
        self.file
    }
}

pub fn create_for_append(path: &Path) -> io::Result<File> {
    File::options()
        .read(true)
        .append(true)
        .create_new(true)
        .open(path)
}

pub fn open_for_append(path: &Path) -> io::Result<File> {
    File::options().read(true).append(true).open(path)
}

pub struct ChainStore {
    dir: PathBuf,
}

impl ChainStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn store_dir(&self) -> &Path {
        &self.dir
    }

    fn chain_filename(&self, chain_hash: &Hash) -> PathBuf {
        let mut filename = self.dir.clone();
        filename.push(format!("{chain_hash}"));
        filename
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
        let filename = self.open_chain_file(chain_hash)?;
        Err(io::Error::other("zounds"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::always::*;
    use crate::block::MutBlock;
    use crate::pksign::SecretSigner;
    use crate::secretseed::Seed;
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

    fn dummy_chain_state() -> ChainState {
        ChainState {
            head: dummy_block_state(),
            tail: dummy_block_state(),
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
    fn test_chainstate_open() {
        let mut buf = [0; BLOCK];
        assert!(ChainState::open(&buf).is_err());
        {
            let seed = Seed::create(&[69; 32]);
            let signer = SecretSigner::new(&seed);
            let state_hash = Hash::from_bytes([42; 32]);
            let mut block = MutBlock::new(&mut buf, &state_hash);
            signer.sign(&mut block);
            block.finalize();
        }
        let block = Block::open(&buf).unwrap();
        let chain = ChainState::open(&buf).unwrap();
        assert_eq!(chain.tail.counter, 0);
        assert_eq!(chain.tail.chain_hash, block.chain_hash());
        assert_eq!(chain.tail.block_hash, block.hash());
        assert_eq!(chain.tail.next_pubkey_hash, block.next_pubkey_hash());
    }

    #[test]
    fn test_chain_open() {
        let mut file = tempfile::tempfile().unwrap();
        assert!(Chain::open(file.try_clone().unwrap()).is_err());
        file.write_all(&[69; BLOCK]).unwrap();
        file.rewind().unwrap();
        assert!(Chain::open(file.try_clone().unwrap()).is_err());

        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&new_valid_first_block()).unwrap();
        file.rewind().unwrap();
        let chain = Chain::open(file).unwrap();
    }

    #[test]
    fn test_chain_read_next() {
        let mut file = tempfile::tempfile().unwrap();
        let mut chain = Chain {
            file: file.try_clone().unwrap(),
            buf: [0; BLOCK],
            state: dummy_chain_state(),
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
        let chainstore = ChainStore::new(dir);
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
        let chainstore = ChainStore::new(tmpdir.path().to_owned());
        let chain_hash = Hash::from_bytes([42; 32]);
        assert!(chainstore.open_chain_file(&chain_hash).is_err()); // File does not exist yet

        let filename = chainstore.chain_filename(&chain_hash);
        create_for_append(&filename).unwrap();
        assert!(chainstore.open_chain_file(&chain_hash).is_ok());
    }

    #[test]
    fn test_chainstore_create_chain_file() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let chainstore = ChainStore::new(tmpdir.path().to_owned());
        let chain_hash = Hash::from_bytes([42; 32]);
        assert!(chainstore.create_chain_file(&chain_hash).is_ok());
        assert!(chainstore.create_chain_file(&chain_hash).is_err()); // File already exists
    }
}
