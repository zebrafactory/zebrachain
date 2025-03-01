//! Writes/reads blocks to/from non-volitile storage and network.

use crate::always::*;
use crate::block::{Block, BlockState};
use crate::fsutil::{chain_filename, create_for_append, open_for_append};
use blake3::Hash;
use std::fs::{File, remove_file};
use std::io;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/*
Chain validation process:

    1. Load first block with Block::from_hash_at_index()
    2. Walk remaining blocks till end of chain using Block::from_previous()

Or when resuming from a checkpoint, the chain validation process is:

    1. Load first block with Block::from_hash_at_index()
    2. Load checkpoint block with Block::from_hash_at_index()
    3. Walk remaining blocks till end of chain using Block::from_previous()
*/

/// Check point a chain for fast reload.
pub struct CheckPoint {
    pub chain_hash: Hash,
    pub block_hash: Hash,
    pub index: u64,
}

impl CheckPoint {
    pub fn new(chain_hash: Hash, block_hash: Hash, index: u64) -> Self {
        Self {
            chain_hash,
            block_hash,
            index,
        }
    }

    pub fn from_block_state(state: &BlockState) -> Self {
        Self::new(state.chain_hash, state.block_hash, state.index)
    }
}

fn validate_chain(file: File, chain_hash: &Hash) -> io::Result<(File, BlockState, BlockState)> {
    let mut file = BufReader::with_capacity(BLOCK * 16, file);
    let mut buf = [0; BLOCK];

    // Read and validate first block
    file.rewind()?;
    file.read_exact(&mut buf)?;
    // FIXME: Add test for when first block has index != 0
    let head = match Block::from_hash_at_index(&buf, chain_hash, 0) {
        Ok(block) => block.state(),
        Err(err) => return Err(err.to_io_error()),
    };

    // Read and validate all remaining blocks till the end of the chain
    let mut tail = head.clone();
    while file.read_exact(&mut buf).is_ok() {
        tail = match Block::from_previous(&buf, &tail) {
            Ok(block) => block.state(),
            Err(err) => return Err(err.to_io_error()),
        };
    }
    Ok((file.into_inner(), head, tail))
}

// Security Warning: This is ONLY secure if `checkpoint` is trustworthy and correct!
fn validate_from_checkpoint(
    mut file: File,
    checkpoint: &CheckPoint,
) -> io::Result<(File, BlockState, BlockState)> {
    let mut buf = [0; BLOCK];

    // Read and validate first block
    file.rewind()?;
    file.read_exact(&mut buf)?;
    let head = match Block::from_hash_at_index(&buf, &checkpoint.chain_hash, 0) {
        Ok(block) => block.state(),
        Err(err) => return Err(err.to_io_error()),
    };

    // Read and validate checkpoint block
    file.seek(SeekFrom::Start(checkpoint.index * BLOCK as u64))?;
    let mut file = BufReader::with_capacity(BLOCK * 16, file);
    file.read_exact(&mut buf)?;
    let mut tail = match Block::from_hash_at_index(&buf, &checkpoint.block_hash, checkpoint.index) {
        Ok(block) => block.state(),
        Err(err) => return Err(err.to_io_error()),
    };

    // Read and validate any remaining blocks till the end of the chain
    while file.read_exact(&mut buf).is_ok() {
        tail = match Block::from_previous(&buf, &tail) {
            Ok(block) => block.state(),
            Err(err) => return Err(err.to_io_error()),
        };
    }
    Ok((file.into_inner(), head, tail))
}

/// Read and write blocks to a file.
pub struct Chain {
    file: File,
    head: BlockState,
    tail: BlockState,
}

impl Chain {
    /// Open and fully validate a chain.
    pub fn open(file: File, chain_hash: &Hash) -> io::Result<Self> {
        let (file, head, tail) = validate_chain(file, chain_hash)?;
        Ok(Self { file, head, tail })
    }

    /// Open and validate a chain from a [CheckPoint] forward.
    ///
    /// This does not fully validate the chain. It validates the first block, the checkpoint block
    /// itself, and any remaining blocks in the chain.
    ///
    /// # Security Note
    ///
    /// This is ONLY secure if `checkpoint` is trustworthy and correct.
    pub fn resume(file: File, checkpoint: &CheckPoint) -> io::Result<Self> {
        let (file, head, tail) = validate_from_checkpoint(file, checkpoint)?;
        Ok(Self { file, head, tail })
    }

    /// Return the number of blocks in the chain.
    pub fn count(&self) -> u64 {
        self.tail.index + 1
    }

    pub fn create(mut file: File, buf: &[u8], chain_hash: &Hash) -> io::Result<Self> {
        match Block::from_hash_at_index(buf, chain_hash, 0) {
            Ok(block) => {
                file.write_all(buf)?;
                Ok(Self {
                    file,
                    head: block.state(),
                    tail: block.state(),
                })
            }
            Err(err) => Err(err.to_io_error()),
        }
    }

    pub fn head(&self) -> &BlockState {
        &self.head
    }

    pub fn tail(&self) -> &BlockState {
        &self.tail
    }

    #[allow(clippy::misnamed_getters)] // Clippy is wrong here
    pub fn chain_hash(&self) -> &Hash {
        &self.head.block_hash
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

    pub fn iter(&self) -> ChainIter {
        ChainIter::new(
            self.file.try_clone().unwrap(),
            *self.chain_hash(),
            self.count(),
        )
    }
}

impl IntoIterator for &Chain {
    type Item = io::Result<BlockState>;
    type IntoIter = ChainIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterate through each [Block] in a [Chain].
pub struct ChainIter {
    file: BufReader<File>,
    chain_hash: Hash,
    count: u64,
    tail: Option<BlockState>,
    buf: [u8; BLOCK],
}

impl ChainIter {
    pub fn new(file: File, chain_hash: Hash, count: u64) -> Self {
        let file = BufReader::with_capacity(BLOCK * 16, file);
        Self {
            file,
            chain_hash,
            count,
            tail: None,
            buf: [0; BLOCK],
        }
    }

    fn index(&self) -> u64 {
        if let Some(tail) = self.tail.as_ref() {
            tail.index + 1
        } else {
            0
        }
    }

    fn next_inner(&mut self) -> io::Result<BlockState> {
        if self.tail.is_none() {
            self.file.rewind()?;
        }
        self.file.read_exact(&mut self.buf)?;
        let blockresult = if let Some(tail) = self.tail.as_ref() {
            Block::from_previous(&self.buf, tail)
        } else {
            Block::from_hash_at_index(&self.buf, &self.chain_hash, 0)
        };
        match blockresult {
            Ok(block) => {
                self.tail = Some(block.state());
                Ok(block.state())
            }
            Err(err) => Err(err.to_io_error()),
        }
    }
}

impl Iterator for ChainIter {
    type Item = io::Result<BlockState>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index() < self.count {
            Some(self.next_inner())
        } else {
            None
        }
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
        chain_filename(&self.dir, chain_hash)
    }

    pub fn open_chain_file(&self, chain_hash: &Hash) -> io::Result<File> {
        let filename = self.chain_filename(chain_hash);
        open_for_append(&filename)
    }

    pub fn create_chain_file(&self, chain_hash: &Hash) -> io::Result<File> {
        let filename = self.chain_filename(chain_hash);
        create_for_append(&filename)
    }

    pub fn remove_chain_file(&self, chain_hash: &Hash) -> io::Result<()> {
        let filename = self.chain_filename(chain_hash);
        remove_file(&filename)
    }

    pub fn open_chain(&self, chain_hash: &Hash) -> io::Result<Chain> {
        let file = self.open_chain_file(chain_hash)?;
        Chain::open(file, chain_hash)
    }

    pub fn resume_chain(&self, checkpoint: &CheckPoint) -> io::Result<Chain> {
        let file = self.open_chain_file(&checkpoint.chain_hash)?;
        Chain::resume(file, checkpoint)
    }

    pub fn create_chain(&self, buf: &[u8], chain_hash: &Hash) -> io::Result<Chain> {
        let file = self.create_chain_file(chain_hash)?;
        Chain::create(file, buf, chain_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pksign::sign_block;
    use crate::secretseed::Seed;
    use crate::testhelpers::{BitFlipper, random_hash, random_request};
    use blake3::Hash;
    use tempfile;

    #[test]
    fn test_validate_chain() {
        let mut file = tempfile::tempfile().unwrap();

        // Generate 1st block
        let mut seed = Seed::auto_create().unwrap();
        let mut buf1 = [0; BLOCK];
        let request1 = random_request();
        let chain_hash = sign_block(&mut buf1, &seed, &request1, None);
        let buf1 = buf1; // Doesn't need to be mutable anymore
        let block1 = Block::from_hash_at_index(&buf1, &chain_hash, 0).unwrap();

        // Write to file, test with a single block
        file.write_all(&buf1).unwrap();
        let (file, head, tail) = validate_chain(file, &chain_hash).unwrap();
        assert_eq!(head, block1.state());
        assert_eq!(tail, head);
        assert_eq!(tail.index, 0);

        // Open a 2nd time, should work the same (file.rewind() should be called):
        let (mut file, head, tail) = validate_chain(file, &chain_hash).unwrap();
        assert_eq!(head, block1.state());
        assert_eq!(tail, head);
        assert_eq!(tail.index, 0);

        // Generate a 2nd block
        let next = seed.auto_advance().unwrap();
        let mut buf2 = [0; BLOCK];
        let request2 = random_request();
        let _block_hash = sign_block(&mut buf2, &next, &request2, Some(&tail));
        seed.commit(next);
        let buf2 = buf2; // Doesn't need to be mutable anymore
        let block2 = Block::from_previous(&buf2, &tail).unwrap();

        // Write to file, test with 2 blocks
        file.write_all(&buf2).unwrap();
        let (mut file, head, tail) = validate_chain(file, &chain_hash).unwrap();
        assert_eq!(head, block1.state());
        assert_eq!(tail, block2.state());
        assert_eq!(tail.index, 1);

        let mut good = Vec::with_capacity(BLOCK * 2);
        good.extend_from_slice(&buf1);
        good.extend_from_slice(&buf2);
        file.rewind().unwrap();
        file.set_len(0).unwrap();
        file.write_all(&good).unwrap();
        let (_, head, tail) = validate_chain(file.try_clone().unwrap(), &chain_hash).unwrap();
        assert_eq!(head, block1.state());
        assert_eq!(tail, block2.state());
        assert_eq!(tail.index, 1);

        for bad in BitFlipper::new(&good) {
            file.rewind().unwrap();
            file.set_len(0).unwrap();
            file.write_all(&bad).unwrap();
            assert!(validate_chain(file.try_clone().unwrap(), &chain_hash).is_err());
        }

        file.rewind().unwrap();
        file.set_len(0).unwrap();
        file.write_all(&good).unwrap();
        let (_, head, tail) = validate_chain(file.try_clone().unwrap(), &chain_hash).unwrap();
        assert_eq!(head, block1.state());
        assert_eq!(tail, block2.state());
        assert_eq!(tail.index, 1);
        // FIXME: We aren't currently handling truncation
        let length = (BLOCK * 2) as u64;
        for reduce in 1..=length {
            assert!(reduce > 0);
            file.set_len(length - reduce).unwrap();
            if reduce > BLOCK as u64 {
                assert!(validate_chain(file.try_clone().unwrap(), &chain_hash).is_err());
            } else {
                assert!(validate_chain(file.try_clone().unwrap(), &chain_hash).is_ok());
            }
        }
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
    fn test_chainstore_remove_chain_file() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let store = ChainStore::new(tmpdir.path());
        let chain_hash = random_hash();
        assert!(store.remove_chain_file(&chain_hash).is_err()); // File does not exist
        assert!(store.create_chain_file(&chain_hash).is_ok());
        assert!(store.remove_chain_file(&chain_hash).is_ok());
        assert!(store.remove_chain_file(&chain_hash).is_err()); // Gone again
    }

    #[test]
    fn test_chainstore_open_chain() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let chainstore = ChainStore::new(tmpdir.path());
        let chain_hash = random_hash();
        assert!(chainstore.open_chain(&chain_hash).is_err());
    }
}
