//! Writes/reads blocks to/from non-volitile storage and network.

use crate::always::*;
use crate::block::{Block, BlockState};
use crate::fsutil::{build_filename, create_for_append, open_for_append};
use blake3::Hash;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
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

    pub fn chain_hash(&self) -> &Hash {
        &self.head.block_hash
    }

    fn read_next(&mut self) -> io::Result<()> {
        self.file.read_exact(&mut self.buf)
    }

    fn read_block(&self, buf: &mut [u8], index: u64) -> io::Result<()> {
        let offset = index * BLOCK as u64;
        self.file.read_exact_at(buf, offset)
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

    pub fn iter(&self) -> ChainIter {
        ChainIter::new(self)
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
    pub fn new(chain: &'a Chain) -> Self {
        Self {
            chain,
            index: 0,
            count: 0,
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

fn demo(chain: Chain) {
    for result in &chain {}
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
    use crate::block::MutBlock;
    use crate::pksign::{sign_block, SecretSigner};
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
    fn test_validate_chain() {
        let file = tempfile::tempfile().unwrap();

        // Generate 1st block
        let seed = Seed::auto_create();
        let mut buf1 = [0; BLOCK];
        let chain_hash = sign_block(&mut buf1, &seed, &random_hash(), None);
        let buf1 = buf1; // Doesn't need to be mutable anymore
        let block1 = Block::from_hash(&buf1, &chain_hash).unwrap();

        // Write to file, test with a single block
        file.write_all_at(&buf1, 0).unwrap(); // Haha, file doesn't need to be mut
        let (head, tail, count) = validate_chain(&file, &chain_hash).unwrap();
        let block1 = Block::from_hash(&buf1, &chain_hash).unwrap();
        assert_eq!(head, block1.state());
        assert_eq!(tail, head);
        assert_eq!(count, 1);

        // Open a 2nd time, should work the same (file cursor position plays no part)
        assert_eq!(
            validate_chain(&file, &chain_hash).unwrap(),
            (block1.state(), block1.state(), 1)
        );

        // Generate the 2nd block
        let next = seed.auto_advance();
        let mut buf2 = [0; BLOCK];
        let block_hash = sign_block(&mut buf2, &next, &random_hash(), Some(&tail));
        let buf2 = buf2; // Doesn't need to be mutable anymore
        let block2 = Block::from_previous(&buf2, &tail).unwrap();

        // Write to file, test with 2 blocks
        file.write_all_at(&buf2, BLOCK as u64).unwrap();
        assert_eq!(
            validate_chain(&file, &chain_hash).unwrap(),
            (block1.state(), block2.state(), 2)
        );
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
