//! Read and write secret blocks in a chain.

use crate::always::*;
use crate::errors::SecretBlockError;
use crate::fsutil::{create_for_append, open_for_append, secret_chain_filename};
use crate::secretblock::SecretBlock;
use crate::secretseed::{Secret, Seed, derive_secret};
use blake3::{Hash, keyed_hash};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use std::fs::{File, remove_file};
use std::io;
use std::io::{BufReader, Read, Seek, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

// Split out of derive_block_secrets() for testability
#[inline]
fn derive_block_secrets_inner(secret: &Secret, index: u64) -> (Secret, Secret) {
    let root = keyed_hash(secret.as_bytes(), &index.to_le_bytes());
    let key = derive_secret(CONTEXT_STORE_KEY, &root);
    let nonce = derive_secret(CONTEXT_STORE_NONCE, &root);
    assert_ne!(key, nonce);
    (key, nonce)
}

// Use a unique key and nonce for each block in the secret chain
fn derive_block_secrets(secret: &Secret, index: u64) -> (Key, Nonce) {
    let (key, nonce) = derive_block_secrets_inner(secret, index);
    let key = Key::from_slice(&key.as_bytes()[..]);
    let nonce = Nonce::from_slice(&nonce.as_bytes()[0..12]);
    (*key, *nonce)
}

fn encrypt_in_place(buf: &mut Vec<u8>, secret: &Secret, index: u64) {
    assert_eq!(buf.len(), SECRET_BLOCK);
    let (key, nonce) = derive_block_secrets(secret, index);
    let cipher = ChaCha20Poly1305::new(&key);
    cipher.encrypt_in_place(&nonce, b"", buf).unwrap(); // This should not fail
    assert_eq!(buf.len(), SECRET_BLOCK_AEAD);
}

fn decrypt_in_place(
    buf: &mut Vec<u8>,
    secret: &Secret,
    index: u64,
) -> Result<(), SecretBlockError> {
    assert_eq!(buf.len(), SECRET_BLOCK_AEAD);
    let (key, nonce) = derive_block_secrets(secret, index);
    let cipher = ChaCha20Poly1305::new(&key);
    if cipher.decrypt_in_place(&nonce, b"", buf).is_err() {
        Err(SecretBlockError::Storage)
    } else {
        assert_eq!(buf.len(), SECRET_BLOCK);
        Ok(())
    }
}

/// Save secret chain to non-volitile storage (encrypted and authenticated).
pub struct SecretChain {
    file: File,
    first_block_hash: Hash,
    tail: SecretBlock,
    secret: Secret,
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
        assert_eq!(buf.len(), SECRET_BLOCK);
        let tail = SecretBlock::from_hash_at_index(&buf[0..SECRET_BLOCK], block_hash, 0).unwrap();
        let first_block_hash = tail.block_hash;
        encrypt_in_place(&mut buf, &secret, 0);
        file.write_all(&buf[..])?;
        Ok(Self {
            file,
            first_block_hash,
            tail,
            secret,
            buf,
        })
    }

    /// Exposes internal secret block buffer as mutable bytes.
    pub fn as_mut_buf(&mut self) -> &mut [u8] {
        self.buf.resize(SECRET_BLOCK, 0); // FIXME: Probably put this somewhere else
        &mut self.buf[..]
    }

    /// Exposed secret block buffer as bytes.
    pub fn as_buf(&self) -> &[u8] {
        &self.buf[0..SECRET_BLOCK]
    }

    /// Mix need entropy into chain and return next [Seed].
    pub fn advance(&self, new_entropy: &Hash) -> Seed {
        self.tail.seed.advance(new_entropy)
    }

    /// FIXME: Probably remove from public API.
    pub fn open(file: File, secret: Secret) -> io::Result<Self> {
        let mut file = BufReader::with_capacity(SECRET_BLOCK_AEAD_READ_BUF, file);
        let mut buf = vec![0; SECRET_BLOCK_AEAD];
        file.read_exact(&mut buf[..])?;
        if let Err(err) = decrypt_in_place(&mut buf, &secret, 0) {
            return Err(err.to_io_error());
        }
        let mut tail = match SecretBlock::open(&buf[..]) {
            Ok(block) => block,
            Err(err) => return Err(err.to_io_error()),
        };
        buf.zeroize();
        buf.resize(SECRET_BLOCK_AEAD, 0);
        let first_block_hash = tail.block_hash;
        while file.read_exact(&mut buf[..]).is_ok() {
            if let Err(err) = decrypt_in_place(&mut buf, &secret, tail.index + 1) {
                return Err(err.to_io_error());
            }
            tail = match SecretBlock::from_previous(&buf[..], &tail) {
                Ok(block) => block,
                Err(err) => {
                    buf.zeroize();
                    return Err(err.to_io_error());
                }
            };
            buf.zeroize();
            buf.resize(SECRET_BLOCK_AEAD, 0);
        }
        Ok(Self {
            file: file.into_inner(),
            first_block_hash,
            tail,
            secret,
            buf,
        })
    }

    /// Number of blocks in this secret chain.
    pub fn count(&self) -> u64 {
        self.tail.index + 1
    }

    /// The [SecretBlock] of the latest block in this secret chain.
    pub fn tail(&self) -> &SecretBlock {
        &self.tail
    }

    /// Append secret block that has been built up in the internal buffer.
    pub fn append(&mut self, block_hash: &Hash) -> io::Result<()> {
        let block = SecretBlock::from_previous(self.as_buf(), &self.tail).unwrap();
        assert_eq!(&block.block_hash, block_hash);
        encrypt_in_place(&mut self.buf, &self.secret, block.index);
        assert_eq!(self.buf.len(), SECRET_BLOCK_AEAD);
        self.file.write_all(&self.buf)?;
        self.tail = block;
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
    type Item = io::Result<SecretBlock>;
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
    tail: Option<SecretBlock>,
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

    fn next_inner(&mut self) -> io::Result<SecretBlock> {
        if self.tail.is_none() {
            self.file.rewind()?;
        }
        self.buf.resize(SECRET_BLOCK_AEAD, 0);
        self.file.read_exact(&mut self.buf)?;
        let index = self.index();
        if let Err(err) = decrypt_in_place(&mut self.buf, &self.secret, index) {
            return Err(err.to_io_error());
        }
        let result = if let Some(tail) = self.tail.as_ref() {
            SecretBlock::from_previous(&self.buf, tail)
        } else {
            SecretBlock::from_hash_at_index(&self.buf, &self.first_block_hash, 0)
        };
        self.buf.zeroize();
        match result {
            Ok(block) => {
                self.tail = Some(block.clone());
                Ok(block)
            }
            Err(err) => Err(err.to_io_error()),
        }
    }
}

impl Iterator for SecretChainIter {
    type Item = io::Result<SecretBlock>;

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
    secret: Secret,
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
    fn derive_secret(&self, chain_hash: &Hash) -> Secret {
        keyed_hash(self.secret.as_bytes(), chain_hash.as_bytes())
    }

    fn chain_filename(&self, chain_hash: &Hash) -> PathBuf {
        secret_chain_filename(&self.dir, chain_hash)
    }

    /// Open a secret chain identified by its public chain-hash.
    pub fn open_chain(&self, chain_hash: &Hash) -> io::Result<SecretChain> {
        let filename = self.chain_filename(chain_hash);
        let file = open_for_append(&filename)?;
        let secret = self.derive_secret(chain_hash);
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
        let secret = self.derive_secret(chain_hash);
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
    fn test_derive_block_secrets_inner() {
        let count: u64 = 4200;
        let mut hset = HashSet::with_capacity(count as usize);
        let secret = generate_secret().unwrap();
        for index in 0..count {
            let (key, nonce) = derive_block_secrets_inner(&secret, index);
            assert!(hset.insert(key));
            assert!(hset.insert(nonce));
        }
        assert_eq!(hset.len(), 2 * count as usize);
    }

    #[test]
    fn test_chacha20poly1305_roundtrip() {
        let mut buf = vec![0; SECRET_BLOCK];
        getrandom::fill(&mut buf).unwrap();
        let h = hash(&buf);
        let secret = generate_secret().unwrap();
        for index in 0..420 {
            encrypt_in_place(&mut buf, &secret, index);
            assert_eq!(buf.len(), SECRET_BLOCK_AEAD);
            assert_ne!(hash(&buf[0..SECRET_BLOCK]), h);
            decrypt_in_place(&mut buf, &secret, index).unwrap();
            assert_eq!(hash(&buf[0..SECRET_BLOCK]), h);
            assert_eq!(hash(&buf), h);
        }
    }

    #[test]
    fn test_chacha20poly1305_error() {
        let mut buf = vec![0; SECRET_BLOCK];
        getrandom::fill(&mut buf).unwrap();
        let h = hash(&buf);
        let secret = generate_secret().unwrap();
        for index in 0..3 {
            encrypt_in_place(&mut buf, &secret, index);
            for mut bad in BitFlipper::new(&buf) {
                assert!(decrypt_in_place(&mut bad, &secret, index).is_err());
            }
            decrypt_in_place(&mut buf, &secret, index).unwrap();
            assert_eq!(hash(&buf), h);
        }
    }

    #[test]
    fn test_chain_create() {
        let mut buf = vec![0; SECRET_BLOCK];
        let payload = random_payload();
        let mut block = MutSecretBlock::new(&mut buf[..], &payload);

        let seed = Seed::auto_create().unwrap();
        block.set_seed(&seed);
        let block_hash = block.finalize();

        let file = tempfile().unwrap();
        let secret = random_hash();

        let result = SecretChain::create(file, secret, buf, &block_hash);
        assert!(result.is_ok());
        let mut file = result.unwrap().into_file();
        file.rewind().unwrap();
        let mut buf = vec![0; SECRET_BLOCK_AEAD];
        file.read_exact(&mut buf[..]).unwrap();
        decrypt_in_place(&mut buf, &secret, 0).unwrap();
        let block = SecretBlock::open(&buf[..]).unwrap();
        assert_eq!(seed, block.seed);
    }

    #[test]
    fn test_chain_open() {
        let mut file = tempfile().unwrap();
        let secret = generate_secret().unwrap();
        assert!(SecretChain::open(file.try_clone().unwrap(), secret.clone()).is_err());
        let mut buf = vec![0; SECRET_BLOCK];

        let seed = Seed::auto_create().unwrap();
        let payload = random_payload();
        let mut block = MutSecretBlock::new(&mut buf, &payload);
        block.set_seed(&seed);
        block.finalize();
        encrypt_in_place(&mut buf, &secret, 0);

        file.write_all(&buf[..]).unwrap();
        file.rewind().unwrap();
        assert_eq!(
            SecretChain::open(file.try_clone().unwrap(), secret)
                .unwrap()
                .tail()
                .seed,
            seed
        );

        getrandom::fill(&mut buf).unwrap();
        file.write_all(&buf).unwrap();
        file.rewind().unwrap();
        assert!(SecretChain::open(file, secret).is_err());
    }

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

    #[test]
    fn test_store_derive_secret() {
        let dir = PathBuf::from("/nope");
        let secret = Hash::from_bytes([42; DIGEST]);
        let store = SecretChainStore::new(&dir, secret);
        let chain_hash = Hash::from_bytes([69; DIGEST]);
        let sec = store.derive_secret(&chain_hash);
        assert_eq!(sec, Hash::from_hex(HEX0).unwrap());
        assert_eq!(sec, keyed_hash(secret.as_bytes(), chain_hash.as_bytes()));
        let secret = random_hash();
        let chain_hash = random_hash();
        let store = SecretChainStore::new(&dir, secret);
        assert_eq!(
            store.derive_secret(&chain_hash),
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
        let secret = random_hash();
        let store = SecretChainStore::new(dir.path(), secret);
        let chain_hash = random_hash();
        assert!(store.open_chain(&chain_hash).is_err());
        let filename = store.chain_filename(&chain_hash);
        let mut file = create_for_append(&filename).unwrap();
        let mut buf = [0; SECRET_BLOCK_AEAD];
        getrandom::fill(&mut buf).unwrap();
        file.write_all(&buf).unwrap();
        file.rewind().unwrap();
        assert!(store.open_chain(&chain_hash).is_err()); // Not valid ChaCha20Poly1305 content

        let mut buf = vec![0; SECRET_BLOCK];
        let seed = Seed::auto_create().unwrap();
        let payload = random_payload();
        let chain_secret = store.derive_secret(&chain_hash);
        assert_eq!(
            chain_secret,
            keyed_hash(secret.as_bytes(), chain_hash.as_bytes())
        );
        let mut block = MutSecretBlock::new(&mut buf, &payload);
        block.set_seed(&seed);
        block.finalize();
        encrypt_in_place(&mut buf, &chain_secret, 0);
        store.remove_chain_file(&chain_hash).unwrap();
        let mut file = create_for_append(&filename).unwrap();
        file.write_all(&buf).unwrap();
        let chain = store.open_chain(&chain_hash).unwrap();
        assert_eq!(chain.tail().seed, seed);
    }

    #[test]
    fn test_store_create_chain() {
        let mut buf = vec![0; SECRET_BLOCK];
        let payload = random_payload();
        let mut block = MutSecretBlock::new(&mut buf[..], &payload);

        let seed = Seed::auto_create().unwrap();
        block.set_seed(&seed);
        let block_hash = block.finalize();

        let dir = TempDir::new().unwrap();
        let secret = random_hash();
        let store = SecretChainStore::new(dir.path(), secret);

        let chain_hash = random_hash();
        let chain = store.create_chain(&chain_hash, buf, &block_hash).unwrap();

        let tail = chain.tail().clone();
        assert_eq!(tail.seed, seed);
        let chain = store.open_chain(&chain_hash).unwrap();
        assert_eq!(chain.tail().seed, seed);
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
