//! Writes/reads blocks to/from non-volitile storage and network.

use crate::always::*;
use crate::block::{Block, BlockError, BlockState};
use crate::fsutil::{build_filename, create_for_append, open_for_append};
use blake3::Hash;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::PathBuf;

/*
For now we will fully validate all chains when opening them.

Validate first block
Check againt external first block hash
Walk chain till last block.
*/

/// Stores state of starting and and ending block.
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

    pub fn from_first_block(block: &Block) -> Self {
        Self {
            head: block.state(),
            tail: block.state(),
        }
    }

    pub fn append(&mut self, buf: &[u8]) -> Result<(), BlockError> {
        let block = Block::from_previous(buf, &self.tail)?;
        self.tail = block.state();
        assert_eq!(self.tail.chain_hash, self.head.block_hash);
        Ok(())
    }
}

/// Read and write blocks to a file.
pub struct Chain {
    file: File,
    buf: [u8; BLOCK],
    pub state: ChainState,
}

impl Chain {
    pub fn open(mut file: File) -> io::Result<Self> {
        let mut buf = [0; BLOCK];
        file.read_exact(&mut buf)?;
        match ChainState::open(&buf) {
            Ok(state) => Ok(Self { file, buf, state }),
            Err(err) => Err(io::Error::other(format!("{err:?}"))),
        }
    }

    pub fn create(mut file: File, block: &Block) -> io::Result<Self> {
        file.write_all(block.as_buf())?;
        let buf = [0; BLOCK];
        let state = ChainState::from_first_block(block);
        Ok(Self { file, buf, state })
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
        match self.state.append(buf) {
            Ok(_) => {
                self.file.write_all(buf)?;
                Ok(&self.state.tail)
            }
            Err(err) => Err(io::Error::other(format!("{err:?}"))),
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
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
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
        Chain::open(file)
    }

    pub fn create_chain(&self, block: &Block) -> io::Result<Chain> {
        // FIXME: check that this is a valid first block (counter=0)
        let chain_hash = block.state().effective_chain_hash();
        let file = self.create_chain_file(&chain_hash)?;
        Chain::create(file, block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MutBlock;
    use crate::pksign::SecretSigner;
    use crate::secretseed::Seed;
    use crate::testhelpers::random_hash;
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
        let chain_hash = random_hash();
        assert!(chainstore.open_chain_file(&chain_hash).is_err()); // File does not exist yet

        let filename = chainstore.chain_filename(&chain_hash);
        create_for_append(&filename).unwrap();
        assert!(chainstore.open_chain_file(&chain_hash).is_ok());
    }

    #[test]
    fn test_chainstore_create_chain_file() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let chainstore = ChainStore::new(tmpdir.path().to_owned());
        let chain_hash = random_hash();
        assert!(chainstore.create_chain_file(&chain_hash).is_ok());
        assert!(chainstore.create_chain_file(&chain_hash).is_err()); // File already exists
    }

    #[test]
    fn test_chainstore_open_chain() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let chainstore = ChainStore::new(tmpdir.path().to_path_buf());
        let chain_hash = random_hash();
        assert!(chainstore.open_chain(&chain_hash).is_err());
    }
}
