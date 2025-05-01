//! Read and write secret blocks in a chain.

use crate::always::*;
use crate::fsutil::{create_for_append, open_for_append, secret_chain_filename};
use crate::secretblock::{SecretBlock, SecretBlockState};
use crate::secretseed::{Secret, Seed};
use blake3::{Hash, keyed_hash};
use std::fs::{File, remove_file};
use std::io;
use std::io::{BufReader, Read, Seek, Write};
use std::path::{Path, PathBuf};

pub(crate) fn derive_chain_secret(store_secret: &Secret, chain_hash: &Hash) -> Secret {
    keyed_hash(store_secret.as_bytes(), chain_hash.as_bytes())
}

/// Save secret chain to non-volitile storage (encrypted and authenticated).
pub struct SecretChain {
    file: File,
    first_block_hash: Hash,
    tail: SecretBlockState,
    pub(crate) secret: Secret,
    buf: Vec<u8>,
}

impl SecretChain {
    /// Create a new secret chain.
    pub fn create(
        mut file: File,
        secret: Secret,
        mut buf: Vec<u8>,
        block_hash: &Hash,
    ) -> io::Result<Self> {
        assert_eq!(buf.len(), SECRET_BLOCK_AEAD);
        file.write_all(&buf)?;
        let block = SecretBlock::new(&mut buf);
        let tail = block.from_hash_at_index(&secret, block_hash, 0).unwrap();
        let first_block_hash = tail.block_hash;
        Ok(Self {
            file,
            first_block_hash,
            tail,
            secret,
            buf,
        })
    }

    /// FIXME: Probably remove from public API.
    pub fn open(file: File, chain_secret: Secret) -> io::Result<Self> {
        let mut file = BufReader::with_capacity(SECRET_BLOCK_AEAD_READ_BUF, file);
        file.rewind()?;
        let mut buf = vec![0; SECRET_BLOCK_AEAD];
        let mut tail = {
            let mut block = SecretBlock::new(&mut buf);
            file.read_exact(block.as_mut_read_buf())?;
            match block.from_index(&chain_secret, 0) {
                Ok(state) => state,
                Err(err) => return Err(err.to_io_error()),
            }
        };
        let first_block_hash = tail.block_hash;
        loop {
            tail = {
                let mut block = SecretBlock::new(&mut buf);
                if file.read_exact(block.as_mut_read_buf()).is_err() {
                    break;
                }
                match block.from_previous(&chain_secret, &tail) {
                    Ok(state) => state,
                    Err(err) => return Err(err.to_io_error()),
                }
            };
        }
        Ok(Self {
            file: file.into_inner(),
            first_block_hash,
            tail,
            secret: chain_secret,
            buf,
        })
    }

    /// Exposes internal secret block buffer as mutable bytes.
    pub fn as_mut_buf(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }

    /// Mix new entropy into chain and return next [Seed].
    pub fn advance(&self, new_entropy: &Hash) -> Seed {
        self.tail.seed.advance(new_entropy)
    }

    /// Number of blocks in this secret chain.
    pub fn count(&self) -> u64 {
        self.tail.index + 1
    }

    /// The [SecretBlock] of the latest block in this secret chain.
    pub fn tail(&self) -> &SecretBlockState {
        &self.tail
    }

    /// Append secret block that has been built up in the internal buffer.
    pub fn append(&mut self, block_hash: &Hash) -> io::Result<()> {
        self.file.write_all(&self.buf)?;
        self.tail = {
            let block = SecretBlock::new(&mut self.buf);
            block.from_previous(&self.secret, &self.tail).unwrap()
        };
        assert_eq!(&self.tail.block_hash, block_hash);
        Ok(())
    }

    /// Consume instance and return underlying file.
    pub fn into_file(self) -> File {
        self.file
    }

    /// Iterate through secret blocks in this secret chain.
    pub fn iter(&self) -> SecretChainIter {
        SecretChainIter::new(
            self.file.try_clone().unwrap(),
            self.secret,
            self.count(),
            self.first_block_hash,
        )
    }
}

impl IntoIterator for &SecretChain {
    type Item = io::Result<SecretBlockState>;
    type IntoIter = SecretChainIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterate through secret blocks contained in a secret chain file.
pub struct SecretChainIter {
    file: BufReader<File>,
    secret: Hash,
    count: u64,
    first_block_hash: Hash,
    tail: Option<SecretBlockState>,
    buf: Vec<u8>,
}

impl SecretChainIter {
    fn new(file: File, secret: Hash, count: u64, first_block_hash: Hash) -> Self {
        let file = BufReader::with_capacity(SECRET_BLOCK_AEAD_READ_BUF, file);
        Self {
            file,
            secret,
            count,
            first_block_hash,
            tail: None,
            buf: vec![0; SECRET_BLOCK_AEAD],
        }
    }

    fn index(&self) -> u64 {
        if let Some(tail) = self.tail.as_ref() {
            tail.index + 1
        } else {
            0
        }
    }

    fn next_inner(&mut self) -> io::Result<SecretBlockState> {
        if self.tail.is_none() {
            self.file.rewind()?;
        }
        let mut block = SecretBlock::new(&mut self.buf);
        self.file.read_exact(block.as_mut_read_buf())?;
        let result = if let Some(tail) = self.tail.as_ref() {
            block.from_previous(&self.secret, tail)
        } else {
            block.from_hash_at_index(&self.secret, &self.first_block_hash, 0)
        };
        match result {
            Ok(state) => {
                self.tail = Some(state);
                Ok(state)
            }
            Err(err) => Err(err.to_io_error()),
        }
    }
}

impl Iterator for SecretChainIter {
    type Item = io::Result<SecretBlockState>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index() < self.count {
            Some(self.next_inner())
        } else {
            None
        }
    }
}

/// Organizes [SecretChain] files in a directory.
pub struct SecretChainStore {
    dir: PathBuf,
    pub(crate) secret: Secret, // FIXME
}

impl SecretChainStore {
    /// Creates a new place for your super secret chains.
    pub fn new(dir: &Path, secret: Secret) -> Self {
        Self {
            dir: dir.to_path_buf(),
            secret,
        }
    }

    // Use a different key for each secret chain file
    fn derive_chain_secret(&self, chain_hash: &Hash) -> Secret {
        derive_chain_secret(&self.secret, chain_hash)
    }

    fn chain_filename(&self, chain_hash: &Hash) -> PathBuf {
        secret_chain_filename(&self.dir, chain_hash)
    }

    /// Open a secret chain identified by its public chain-hash.
    pub fn open_chain(&self, chain_hash: &Hash) -> io::Result<SecretChain> {
        let filename = self.chain_filename(chain_hash);
        let file = open_for_append(&filename)?;
        let secret = self.derive_chain_secret(chain_hash);
        SecretChain::open(file, secret)
    }

    /// Create a new secret chain.
    pub fn create_chain(
        &self,
        chain_hash: &Hash,
        buf: Vec<u8>,
        block_hash: &Hash,
    ) -> io::Result<SecretChain> {
        let filename = self.chain_filename(chain_hash);
        let file = create_for_append(&filename)?;
        let secret = self.derive_chain_secret(chain_hash);
        SecretChain::create(file, secret, buf, block_hash)
    }

    /// Remove secret chain file.
    pub fn remove_chain_file(&self, chain_hash: &Hash) -> io::Result<()> {
        let filename = self.chain_filename(chain_hash);
        remove_file(&filename)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secretblock::MutSecretBlock;
    use crate::secretseed::generate_secret;
    use crate::testhelpers::{BitFlipper, random_hash, random_payload};
    use blake3::hash;
    use getrandom;
    use std::collections::HashSet;
    use std::io::Seek;
    use tempfile::{TempDir, tempfile};

    const HEX0: &str = "1b695d50d6105777ed7b5a0bb0bce5484ddca1d6b16bbb0c7bac90599c59370e";

    #[test]
    fn test_chain_create_open() {
        let mut buf = vec![0; SECRET_BLOCK];
        let payload = random_payload();
        let mut block = MutSecretBlock::new(&mut buf, &payload);

        let seed = Seed::auto_create().unwrap();
        block.set_seed(&seed);

        let chain_secret = random_hash();
        let block_hash = block.finalize(&chain_secret);

        let mut buf2 = buf.clone();
        let state = SecretBlock::new(&mut buf2)
            .from_hash_at_index(&chain_secret, &block_hash, 0)
            .unwrap();

        let file = tempfile().unwrap();
        let chain =
            SecretChain::create(file.try_clone().unwrap(), chain_secret, buf, &block_hash).unwrap();
        assert_eq!(chain.tail(), &state);

        // Reopen chain, test SecretChain::open()
        let chain = SecretChain::open(file, chain_secret).unwrap();
        assert_eq!(chain.tail(), &state);
    }

    #[test]
    fn test_chain_open() {
        let mut file = tempfile().unwrap();
        let chain_secret = generate_secret().unwrap();

        // Empty file
        assert!(SecretChain::open(file.try_clone().unwrap(), chain_secret).is_err());

        // A secret aead block full of random data
        let mut buf = vec![0; SECRET_BLOCK_AEAD];
        getrandom::fill(&mut buf).unwrap();
        file.write_all(&buf).unwrap();
        file.rewind().unwrap();
        assert!(SecretChain::open(file, chain_secret).is_err());
    }

    /*
    #[test]
    fn test_chain_append() {
        let mut buf = vec![0; SECRET_BLOCK];
        let payload = random_payload();
        let mut block = MutSecretBlock::new(&mut buf[..], &payload);

        let mut seed = Seed::auto_create().unwrap();
        block.set_seed(&seed);
        let block_hash = block.finalize();

        let file = tempfile().unwrap();
        let secret = random_hash();
        let mut chain = SecretChain::create(file, secret, buf, &block_hash).unwrap();
        assert_eq!(chain.count(), 1);
        for i in 2..69 {
            seed = seed.auto_advance().unwrap();
            let payload = random_payload();
            let tail = chain.tail().clone();
            let mut block = MutSecretBlock::new(chain.as_mut_buf(), &payload);
            block.set_previous(&tail);
            block.set_seed(&seed);
            let block_hash = block.finalize();
            chain.append(&block_hash).unwrap();
            assert_eq!(chain.count(), i);
        }
        let mut file = chain.into_file();
        file.rewind().unwrap();
        SecretChain::open(file, secret).unwrap();
    }
    */

    #[test]
    fn test_store_derive_secret() {
        let dir = PathBuf::from("/nope");
        let secret = Hash::from_bytes([42; DIGEST]);
        let store = SecretChainStore::new(&dir, secret);
        let chain_hash = Hash::from_bytes([69; DIGEST]);
        let sec = store.derive_chain_secret(&chain_hash);
        assert_eq!(sec, Hash::from_hex(HEX0).unwrap());
        assert_eq!(sec, keyed_hash(secret.as_bytes(), chain_hash.as_bytes()));
        let secret = random_hash();
        let chain_hash = random_hash();
        let store = SecretChainStore::new(&dir, secret);
        assert_eq!(
            store.derive_chain_secret(&chain_hash),
            keyed_hash(secret.as_bytes(), chain_hash.as_bytes())
        );
    }

    #[test]
    fn test_store_chain_filename() {
        let dir = PathBuf::from("/nope");
        let secret = generate_secret().unwrap();
        let store = SecretChainStore::new(dir.as_path(), secret);
        let chain_hash = Hash::from_bytes([69; DIGEST]);
        assert_eq!(
            store.chain_filename(&chain_hash),
            PathBuf::from(
                "/nope/4545454545454545454545454545454545454545454545454545454545454545.secret"
            )
        );
        let chain_hash = random_hash();
        assert_eq!(
            store.chain_filename(&chain_hash),
            PathBuf::from(format!("/nope/{chain_hash}.secret"))
        );
    }

    #[test]
    fn test_store_open_chain() {
        let dir = TempDir::new().unwrap();
        let store_secret = random_hash();
        let store = SecretChainStore::new(dir.path(), store_secret);

        let chain_hash = random_hash();
        assert!(store.open_chain(&chain_hash).is_err());
        let filename = store.chain_filename(&chain_hash);

        let mut file = create_for_append(&filename).unwrap();
        let mut buf = [0; SECRET_BLOCK_AEAD];
        getrandom::fill(&mut buf).unwrap();
        file.write_all(&buf).unwrap();
        file.rewind().unwrap();
        assert!(store.open_chain(&chain_hash).is_err()); // Not valid ChaCha20Poly1305 content
    }

    #[test]
    fn test_store_create_chain_open() {
        let store_secret = random_hash();
        let chain_hash = random_hash();
        let chain_secret = derive_chain_secret(&store_secret, &chain_hash);
        let seed = Seed::auto_create().unwrap();
        let payload = random_payload();

        let mut buf = vec![0; SECRET_BLOCK];
        let mut block = MutSecretBlock::new(&mut buf, &payload);
        block.set_seed(&seed);
        let block_hash = block.finalize(&chain_secret);

        let dir = TempDir::new().unwrap();
        let store = SecretChainStore::new(dir.path(), store_secret);
        let chain = store.create_chain(&chain_hash, buf, &block_hash).unwrap();

        assert_ne!(chain.secret, store_secret);
        assert_eq!(chain.secret, chain_secret);
        let state = chain.tail().clone();
        assert_eq!(state.payload, payload);
        assert_eq!(state.seed, seed);

        // Reopen the chain
        let chain = store.open_chain(&chain_hash).unwrap();
        assert_eq!(chain.tail(), &state);
    }

    #[test]
    fn test_store_remove_file() {
        let dir = TempDir::new().unwrap();
        let secret = random_hash();
        let store = SecretChainStore::new(dir.path(), secret);
        let chain_hash = random_hash();
        assert!(store.remove_chain_file(&chain_hash).is_err());
        let filename = store.chain_filename(&chain_hash);
        create_for_append(&filename).unwrap();
        assert!(store.remove_chain_file(&chain_hash).is_ok());
        assert!(store.remove_chain_file(&chain_hash).is_err());
    }
}
