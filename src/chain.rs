//! Writes/reads blocks to/from non-volitile storage and network.

use crate::always::*;
use crate::block::{Block, BlockState};
use crate::fsutil::{build_filename, create_for_append, open_for_append};
use blake3::Hash;
use std::fs::File;
use std::io;
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

/*
For now we will fully validate all chains when opening them.

Validate first block
Check againt external first block hash
Walk chain till last block.
*/

fn validate_chain(file: &File, chain_hash: &Hash) -> io::Result<(BlockState, BlockState, u64)> {
    let mut buf = [0; BLOCK];
    file.read_exact_at(&mut buf, 0)?;
    let head = match Block::from_hash(&buf, chain_hash) {
        Ok(block) => block.state(),
        Err(err) => return Err(err.to_io_error()),
    };
    let mut tail = head.clone();
    let mut index = 1;
    while file.read_exact_at(&mut buf, index * BLOCK as u64).is_ok() {
        index += 1;
        tail = match Block::from_previous(&buf, &tail) {
            Ok(block) => block.state(),
            Err(err) => return Err(err.to_io_error()),
        };
    }
    Ok((head, tail, index))
}

/// Read and write blocks to a file.
pub struct Chain {
    file: File,
    pub head: BlockState,
    pub tail: BlockState,
    count: u64,
}

impl Chain {
    pub fn open(file: File, chain_hash: &Hash) -> io::Result<Self> {
        let (head, tail, count) = validate_chain(&file, chain_hash)?;
        Ok(Self {
            file,
            head,
            tail,
            count,
        })
    }

    pub fn create(file: File, buf: &[u8], chain_hash: &Hash) -> io::Result<Self> {
        match Block::from_hash(buf, chain_hash) {
            Ok(block) => {
                file.write_all_at(buf, 0)?;
                Ok(Self {
                    file,
                    head: block.state(),
                    tail: block.state(),
                    count: 1,
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

    pub fn chain_hash(&self) -> &Hash {
        &self.head.block_hash
    }

    fn read_block(&self, buf: &mut [u8], index: u64) -> io::Result<()> {
        let offset = index * BLOCK as u64;
        self.file.read_exact_at(buf, offset)
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
        ChainIter::new(self, self.count)
    }
}

impl<'a> IntoIterator for &'a Chain {
    type Item = io::Result<BlockState>;
    type IntoIter = ChainIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct ChainIter<'a> {
    chain: &'a Chain,
    index: u64,
    count: u64,
    tail: Option<BlockState>,
}

impl<'a> ChainIter<'a> {
    pub fn new(chain: &'a Chain, count: u64) -> Self {
        Self {
            chain,
            index: 0,
            count,
            tail: None,
        }
    }

    fn next_inner(&mut self) -> io::Result<BlockState> {
        assert!(self.index < self.count);
        let mut buf = [0; BLOCK];
        self.chain.read_block(&mut buf, self.index)?;
        self.index += 1;

        let blockresult = if let Some(tail) = self.tail.as_ref() {
            Block::from_previous(&buf, tail)
        } else {
            Block::from_hash(&buf, self.chain.chain_hash())
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

impl Iterator for ChainIter<'_> {
    type Item = io::Result<BlockState>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.count {
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

    pub fn create_chain(&self, buf: &[u8], chain_hash: &Hash) -> io::Result<Chain> {
        let file = self.create_chain_file(chain_hash)?;
        Chain::create(file, buf, chain_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::SigningRequest;
    use crate::pksign::sign_block;
    use crate::secretseed::{random_hash, Seed};
    use crate::testhelpers::BitFlipper;
    use blake3::Hash;
    use tempfile;

    #[test]
    fn test_validate_chain() {
        let file = tempfile::tempfile().unwrap();

        // Generate 1st block
        let mut seed = Seed::auto_create();
        let mut buf1 = [0; BLOCK];
        let req1 = &SigningRequest::new(random_hash(), random_hash());
        let chain_hash = sign_block(&mut buf1, &seed, &req1, None);
        let buf1 = buf1; // Doesn't need to be mutable anymore
        let block1 = Block::from_hash(&buf1, &chain_hash).unwrap();

        // Write to file, test with a single block
        file.write_all_at(&buf1, 0).unwrap(); // Haha, file doesn't need to be mut
        let (head, tail, count) = validate_chain(&file, &chain_hash).unwrap();
        assert_eq!(head, block1.state());
        assert_eq!(tail, head);
        assert_eq!(count, 1);

        // Open a 2nd time, should work the same (file cursor position plays no part)
        assert_eq!(
            validate_chain(&file, &chain_hash).unwrap(),
            (block1.state(), block1.state(), 1)
        );

        // Generate a 2nd block
        let next = seed.auto_advance();
        let mut buf2 = [0; BLOCK];
        let req2 = &SigningRequest::new(random_hash(), random_hash());
        let _block_hash = sign_block(&mut buf2, &next, &req2, Some(&tail));
        seed.commit(next);
        let buf2 = buf2; // Doesn't need to be mutable anymore
        let block2 = Block::from_previous(&buf2, &tail).unwrap();

        // Write to file, test with 2 blocks
        file.write_all_at(&buf2, BLOCK as u64).unwrap();
        assert_eq!(
            validate_chain(&file, &chain_hash).unwrap(),
            (block1.state(), block2.state(), 2)
        );

        for bad in BitFlipper::new(&buf1) {
            file.write_all_at(&bad, 0).unwrap();
            assert!(validate_chain(&file, &chain_hash).is_err());
        }

        for bad in BitFlipper::new(&buf2) {
            file.write_all_at(&bad, BLOCK as u64).unwrap();
            assert!(validate_chain(&file, &chain_hash).is_err());
        }

        file.write_all_at(&buf1, 0).unwrap();
        file.write_all_at(&buf2, BLOCK as u64).unwrap();
        assert!(validate_chain(&file, &chain_hash).is_ok());

        // FIXME: We aren't currently handling truncation
        let length = (BLOCK * 2) as u64;
        for reduce in 1..=length {
            assert!(reduce > 0);
            file.set_len(length - reduce).unwrap();
            if reduce > BLOCK as u64 {
                assert!(validate_chain(&file, &chain_hash).is_err());
            } else {
                assert!(validate_chain(&file, &chain_hash).is_ok());
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
    fn test_chainstore_open_chain() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let chainstore = ChainStore::new(tmpdir.path());
        let chain_hash = random_hash();
        assert!(chainstore.open_chain(&chain_hash).is_err());
    }
}
