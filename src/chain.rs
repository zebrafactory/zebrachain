//! Writes/reads blocks to/from non-volatile storage and network.

use crate::always::*;
use crate::fsutil::{chain_filename, create_for_append, open_for_append};
use crate::{Block, BlockState, CheckPoint, Hash};
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

fn validate_chain(file: File, chain_hash: &Hash) -> io::Result<(File, BlockState, BlockState)> {
    let mut file = BufReader::with_capacity(BLOCK * 16, file);
    let mut buf = [0; BLOCK];

    // Read and validate first block
    file.rewind()?;
    file.read_exact(&mut buf)?;
    let head = match Block::new(&buf).from_hash_at_index(chain_hash, 0) {
        Ok(state) => state,
        Err(err) => return Err(err.to_io_error()),
    };

    // Read and validate all remaining blocks till the end of the chain
    let mut tail = head.clone();
    while file.read_exact(&mut buf).is_ok() {
        tail = match Block::new(&buf).from_previous(&tail) {
            Ok(state) => state,
            Err(err) => return Err(err.to_io_error()),
        };
    }
    // read_exact() exited the loop above because either (1) it read zero bytes in which case we
    // reached the end of the file at an expected multiple of the BLOCK size or (2) it read at
    // least one byte but less than BLOCK bytes in which case we encountered a partially written
    // block that should be truncated. Either way, this truncation should be safe and correct:
    let mut file = file.into_inner();
    file.set_len((tail.block_index + 1) * BLOCK as u64)?;
    // We need to seek to the end of the file after truncation
    file.seek(SeekFrom::End(0))?;
    Ok((file, head, tail))
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
    let head = match Block::new(&buf).from_hash_at_index(&checkpoint.chain_hash, 0) {
        Ok(state) => state,
        Err(err) => return Err(err.to_io_error()),
    };

    // Read and validate checkpoint block
    file.seek(SeekFrom::Start(checkpoint.block_index * BLOCK as u64))?;
    let mut file = BufReader::with_capacity(BLOCK_READ_BUF, file);
    file.read_exact(&mut buf)?;
    let mut tail = match Block::new(&buf).from_checkpoint(checkpoint) {
        Ok(state) => state,
        Err(err) => return Err(err.to_io_error()),
    };

    // Read and validate any remaining blocks till the end of the chain
    while file.read_exact(&mut buf).is_ok() {
        tail = match Block::new(&buf).from_previous(&tail) {
            Ok(state) => state,
            Err(err) => return Err(err.to_io_error()),
        };
    }
    let mut file = file.into_inner();
    file.set_len((tail.block_index + 1) * BLOCK as u64)?;
    // We need to seek to the end of the file after truncation
    file.seek(SeekFrom::End(0))?;
    Ok((file, head, tail))
}

/// Read and write blocks to a file.
pub struct Chain {
    file: File,
    head: BlockState,
    tail: BlockState,
}

impl Chain {
    /// Create a new Chain file.
    pub fn create(mut file: File, buf: &[u8], chain_hash: &Hash) -> io::Result<Self> {
        match Block::new(buf).from_hash_at_index(chain_hash, 0) {
            Ok(state) => {
                file.write_all(buf)?;
                Ok(Self {
                    file,
                    head: state.clone(),
                    tail: state,
                })
            }
            Err(err) => Err(err.to_io_error()),
        }
    }

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

    /// Validate block in buffer and append to chain if valid.
    pub fn append(&mut self, buf: &[u8]) -> io::Result<&BlockState> {
        match Block::new(buf).from_previous(&self.tail) {
            Ok(state) => {
                self.file.write_all(buf)?;
                self.tail = state;
                Ok(&self.tail)
            }
            Err(err) => Err(err.to_io_error()),
        }
    }

    /// Return the number of blocks in the chain.
    pub fn count(&self) -> u64 {
        self.tail.block_index + 1
    }

    /// Reference to [BlockState] of first block in chain.
    pub fn head(&self) -> &BlockState {
        &self.head
    }

    /// Reference to [BlockState] of latest block in chain.
    pub fn tail(&self) -> &BlockState {
        &self.tail
    }

    /// The chain hash.
    #[allow(clippy::misnamed_getters)] // Clippy is wrong here
    pub fn chain_hash(&self) -> &Hash {
        &self.head.block_hash
    }

    /// Iterate through blocks in this chain.
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
    fn new(file: File, chain_hash: Hash, count: u64) -> Self {
        let file = BufReader::with_capacity(BLOCK_READ_BUF, file);
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
            tail.block_index + 1
        } else {
            0
        }
    }

    fn next_inner(&mut self) -> io::Result<BlockState> {
        if self.tail.is_none() {
            self.file.rewind()?;
        }
        self.file.read_exact(&mut self.buf)?;
        let block = Block::new(&self.buf);
        let blockresult = if let Some(tail) = self.tail.as_ref() {
            block.from_previous(tail)
        } else {
            block.from_hash_at_index(&self.chain_hash, 0)
        };
        match blockresult {
            Ok(state) => {
                self.tail = Some(state.clone());
                Ok(state)
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
    /// Create a chain store.
    ///
    /// This has no side effects, performs no file system operations.
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    /// Create a new chain identified by `chain_hash` whose 1st block is in `buf`.
    pub fn create_chain(&self, buf: &[u8], chain_hash: &Hash) -> io::Result<Chain> {
        let file = self.create_chain_file(chain_hash)?;
        Chain::create(file, buf, chain_hash)
    }

    /// Open and fully validate the chain identified by `chain_hash`.
    pub fn open_chain(&self, chain_hash: &Hash) -> io::Result<Chain> {
        let file = self.open_chain_file(chain_hash)?;
        Chain::open(file, chain_hash)
    }

    /// Open and partially validate a chain from a `checkpoint` forward.
    pub fn resume_chain(&self, checkpoint: &CheckPoint) -> io::Result<Chain> {
        let file = self.open_chain_file(&checkpoint.chain_hash)?;
        Chain::resume(file, checkpoint)
    }

    /// List chains in this chain store.
    pub fn list_chains(&self) -> io::Result<Vec<Hash>> {
        let mut list = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            if let Some(osname) = entry.path().file_name() {
                if let Some(name) = osname.to_str() {
                    if let Ok(hash) = Hash::from_z32(name.as_bytes()) {
                        list.push(hash);
                    }
                }
            }
        }
        //list.sort(); // FIXME: Hash needs Ord
        Ok(list)
    }

    /// Return the path of the chain file identified by `chain_hash`.
    pub fn chain_filename(&self, chain_hash: &Hash) -> PathBuf {
        chain_filename(&self.dir, chain_hash)
    }

    /// Open the existing chain file identified by `chain_hash`.
    pub fn open_chain_file(&self, chain_hash: &Hash) -> io::Result<File> {
        let filename = self.chain_filename(chain_hash);
        open_for_append(&filename)
    }

    /// Create a new chain file identified by `chain_hash`.
    pub fn create_chain_file(&self, chain_hash: &Hash) -> io::Result<File> {
        let filename = self.chain_filename(chain_hash);
        create_for_append(&filename)
    }

    /// Remove the chain file identified by `chain_hash`.
    pub fn remove_chain_file(&self, chain_hash: &Hash) -> io::Result<()> {
        let filename = self.chain_filename(chain_hash);
        remove_file(&filename)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhelpers::{BitFlipper, random_hash, random_payload};
    use crate::{Hash, MutBlock, Seed};
    use tempfile;

    #[test]
    fn test_validate_chain() {
        let mut file = tempfile::tempfile().unwrap();

        // Generate 1st block
        let seed = Seed::generate().unwrap();
        let mut buf1 = [0; BLOCK];
        let payload1 = random_payload();
        let mut block = MutBlock::new(&mut buf1, &payload1);
        block.sign(&seed);
        let chain_hash = block.finalize();
        let buf1 = buf1; // Doesn't need to be mutable anymore
        let state1 = Block::new(&buf1)
            .from_hash_at_index(&chain_hash, 0)
            .unwrap();

        // Write to file, test with a single block
        file.write_all(&buf1).unwrap();
        let (file, head, tail) = validate_chain(file, &chain_hash).unwrap();
        assert_eq!(head, state1);
        assert_eq!(tail, head);
        assert_eq!(head.block_index, 0);
        assert_eq!(tail.block_index, 0);

        // Open a 2nd time, should work the same (file.rewind() should be called):
        let (mut file, head, tail) = validate_chain(file, &chain_hash).unwrap();
        assert_eq!(head, state1);
        assert_eq!(tail, head);
        assert_eq!(head.block_index, 0);
        assert_eq!(tail.block_index, 0);

        // Write a single extra byte at end. If truncation isn't done correctly when reopening the chain
        // the chain will be in an invalid state after the next block is written, and validation will fail
        // with BlockError::Content the next time the chain is opened.
        file.write_all(b"0").unwrap();
        let (mut file, head, tail) = validate_chain(file, &chain_hash).unwrap();
        assert_eq!(head, state1);
        assert_eq!(tail, state1);

        // Generate a 2nd block
        let next = seed.advance().unwrap();
        let mut buf2 = [0; BLOCK];
        let payload2 = random_payload();
        let mut block = MutBlock::new(&mut buf2, &payload2);
        block.set_previous(&tail);
        block.sign(&next);
        let _block_hash = block.finalize();
        let buf2 = buf2; // Doesn't need to be mutable anymore
        let state2 = Block::new(&buf2).from_previous(&tail).unwrap();

        // Write to file, test with 2 blocks
        file.write_all(&buf2).unwrap();
        let (mut file, head, tail) = validate_chain(file, &chain_hash).unwrap();
        assert_eq!(head, state1);
        assert_eq!(tail, state2);
        assert_eq!(head.block_index, 0);
        assert_eq!(tail.block_index, 1);

        let mut good = Vec::with_capacity(BLOCK * 2);
        good.extend_from_slice(&buf1);
        good.extend_from_slice(&buf2);
        file.rewind().unwrap();
        file.set_len(0).unwrap();
        file.write_all(&good).unwrap();
        let (_, head, tail) = validate_chain(file.try_clone().unwrap(), &chain_hash).unwrap();
        assert_eq!(head, state1);
        assert_eq!(tail, state2);
        assert_eq!(tail.block_index, 1);

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
        assert_eq!(head, state1);
        assert_eq!(tail, state2);
        assert_eq!(tail.block_index, 1);
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
    fn test_validate_chain_bad_first_block() {
        // Test a first block that has a non-zero block_index but is other wise valid
        let mut buf = [0; BLOCK];
        let payload = random_payload();
        let mut block = MutBlock::new(&mut buf, &payload);

        // Set index to 1
        block.buf[INDEX_RANGE].copy_from_slice(&1u64.to_le_bytes());

        let seed = Seed::generate().unwrap();
        block.sign(&seed);
        let chain_hash = block.finalize();

        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&buf).unwrap();

        assert!(validate_chain(file, &chain_hash).is_err());
    }

    #[test]
    fn test_chainstore_chain_filename() {
        let dir = PathBuf::from("/tmp/stuff/junk");
        let chainstore = ChainStore::new(&dir);
        let chain_hash = Hash::from_bytes([42; DIGEST]);
        assert_eq!(
            chainstore.chain_filename(&chain_hash),
            PathBuf::from(
                "/tmp/stuff/junk/9CP6OELE9CP6OELE9CP6OELE9CP6OELE9CP6OELE9CP6OELE9CP6OELE9CP6OELE"
            )
        );
    }

    #[test]
    fn test_chainstore_list_chains() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let chainstore = ChainStore::new(tmpdir.path());
        assert_eq!(chainstore.list_chains().unwrap(), []);
        let hash = random_hash();
        let name = tmpdir.path().join(&hash.to_z32_string());
        create_for_append(&name).unwrap();
        assert_eq!(chainstore.list_chains().unwrap(), [hash]);

        create_for_append(&tmpdir.path().join("foo")).unwrap();
        create_for_append(&tmpdir.path().join("bar")).unwrap();
        assert_eq!(chainstore.list_chains().unwrap(), [hash]);
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
