//! Read and write secret blocks in a chain.

use crate::always::*;
use crate::block::SigningRequest;
use crate::fsutil::{create_for_append, open_for_append, secret_chain_filename};
use crate::secretblock::{MutSecretBlock, SecretBlock};
use crate::secretseed::{derive, Secret, Seed};
use blake3::{keyed_hash, Hash};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use std::fs::{remove_file, File};
use std::io;
use std::io::{BufReader, Read, Seek, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum StorageError {
    Bad,
}

impl StorageError {
    // FIXME: Is there is a Rustier way of doing this? Feedback encouraged.
    pub fn to_io_error(&self) -> io::Error {
        io::Error::other(format!("StorageError::{self:?}"))
    }
}

// Split out of derive_block_secrets() for testability
#[inline]
fn derive_block_secrets_inner(secret: &Secret, index: u64) -> (Secret, Secret) {
    let root = keyed_hash(secret.as_bytes(), &index.to_le_bytes());
    let key = derive(STORAGE_KEY_CONTEXT, &root);
    let nonce = derive(STORAGE_NONCE_CONTEXT, &root);
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

fn decrypt_in_place(buf: &mut Vec<u8>, secret: &Secret, index: u64) -> Result<(), StorageError> {
    assert_eq!(buf.len(), SECRET_BLOCK_AEAD);
    let (key, nonce) = derive_block_secrets(secret, index);
    let cipher = ChaCha20Poly1305::new(&key);
    if cipher.decrypt_in_place(&nonce, b"", buf).is_err() {
        Err(StorageError::Bad)
    } else {
        assert_eq!(buf.len(), SECRET_BLOCK);
        Ok(())
    }
}

/// Save secret chain to non-volitile storage (encrypted and authenticated).
pub struct SecretChain {
    file: File,
    tail: SecretBlock,
    secret: Secret,
    buf: Vec<u8>,
}

impl SecretChain {
    pub fn create(
        mut file: File,
        secret: Secret,
        seed: &Seed,
        request: &SigningRequest,
    ) -> io::Result<Self> {
        let mut buf = vec![0; SECRET_BLOCK];
        let tail = MutSecretBlock::new(&mut buf, seed, request).finalize();
        encrypt_in_place(&mut buf, &secret, 0);
        file.write_all(&buf[..])?;
        Ok(Self {
            file,
            tail,
            secret,
            buf,
        })
    }

    pub fn auto_advance(&self) -> Seed {
        self.tail.seed.auto_advance().unwrap()
    }

    pub fn open(mut file: File, secret: Secret) -> io::Result<Self> {
        let mut buf = vec![0; SECRET_BLOCK_AEAD];
        file.read_exact(&mut buf[..])?;
        if let Err(err) = decrypt_in_place(&mut buf, &secret, 0) {
            return Err(err.to_io_error());
        }
        let mut tail = match SecretBlock::open(&buf[..]) {
            Ok(block) => block,
            Err(err) => return Err(err.to_io_error()),
        };
        buf.resize(SECRET_BLOCK_AEAD, 0);
        while file.read_exact(&mut buf[..]).is_ok() {
            if let Err(err) = decrypt_in_place(&mut buf, &secret, tail.index + 1) {
                return Err(err.to_io_error());
            }
            tail = match SecretBlock::from_previous(&buf[..], &tail) {
                Ok(block) => block,
                Err(err) => return Err(err.to_io_error()),
            };
            buf.resize(SECRET_BLOCK_AEAD, 0);
        }
        Ok(Self {
            file,
            tail,
            secret,
            buf,
        })
    }

    pub fn count(&self) -> u64 {
        self.tail.index + 1
    }

    pub fn tail(&self) -> &SecretBlock {
        &self.tail
    }

    pub fn commit(&mut self, seed: &Seed, request: &SigningRequest) -> io::Result<()> {
        // FIXME: Check SeedSequence here like Seed.commit() does
        self.buf.resize(SECRET_BLOCK, 0);
        let mut block = MutSecretBlock::new(&mut self.buf[..], seed, request);
        block.set_previous(&self.tail);
        let block = block.finalize();
        encrypt_in_place(&mut self.buf, &self.secret, block.index);
        assert_eq!(self.buf.len(), SECRET_BLOCK_AEAD);
        self.file.write_all(&self.buf)?;
        self.tail = block;
        Ok(())
    }

    pub fn into_file(self) -> File {
        self.file
    }

    pub fn iter(&self) -> SecretChainIter {
        SecretChainIter::new(self.file.try_clone().unwrap(), self.secret, self.count())
    }
}

impl IntoIterator for &SecretChain {
    type Item = io::Result<SecretBlock>;
    type IntoIter = SecretChainIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct SecretChainIter {
    file: BufReader<File>,
    secret: Hash,
    count: u64,
    tail: Option<SecretBlock>,
    buf: Vec<u8>,
}

impl SecretChainIter {
    pub fn new(file: File, secret: Hash, count: u64) -> Self {
        let file = BufReader::with_capacity(SECRET_BLOCK_AEAD * 16, file);
        Self {
            file,
            secret,
            count,
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
            SecretBlock::from_previous(&self.buf[..], tail)
        } else {
            SecretBlock::open(&self.buf)
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

    pub fn open_chain(&self, chain_hash: &Hash) -> io::Result<SecretChain> {
        let filename = self.chain_filename(chain_hash);
        let file = open_for_append(&filename)?;
        let secret = self.derive_secret(chain_hash);
        SecretChain::open(file, secret)
    }

    pub fn create_chain(
        &self,
        chain_hash: &Hash,
        seed: &Seed,
        request: &SigningRequest,
    ) -> io::Result<SecretChain> {
        let filename = self.chain_filename(chain_hash);
        let file = create_for_append(&filename)?;
        let secret = self.derive_secret(chain_hash);
        SecretChain::create(file, secret, seed, request)
    }

    pub fn remove_chain_file(&self, chain_hash: &Hash) -> io::Result<()> {
        let filename = self.chain_filename(chain_hash);
        remove_file(&filename)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secretseed::random_secret;
    use crate::testhelpers::{random_hash, random_request, BitFlipper};
    use blake3::hash;
    use getrandom;
    use std::collections::HashSet;
    use std::io::Seek;
    use tempfile::{tempfile, TempDir};

    const HEX0: &str = "1b695d50d6105777ed7b5a0bb0bce5484ddca1d6b16bbb0c7bac90599c59370e";

    #[test]
    fn test_derive_block_secrets_inner() {
        let count: u64 = 4200;
        let mut hset = HashSet::with_capacity(count as usize);
        let secret = random_secret().unwrap();
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
        let secret = random_secret().unwrap();
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
        let secret = random_secret().unwrap();
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
        let file = tempfile().unwrap();
        let secret = random_secret().unwrap();
        let seed = Seed::auto_create().unwrap();
        let request = random_request();
        let result = SecretChain::create(file, secret, &seed, &request);
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
        let secret = random_secret().unwrap();
        assert!(SecretChain::open(file.try_clone().unwrap(), secret.clone()).is_err());
        let mut buf = vec![0; SECRET_BLOCK];

        let seed = Seed::auto_create().unwrap();
        let request = random_request();
        MutSecretBlock::new(&mut buf, &seed, &request).finalize();
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
    fn test_chain_advance_and_commit() {
        let file = tempfile().unwrap();
        let secret = random_secret().unwrap();
        let mut seed = Seed::auto_create().unwrap();
        let request = random_request();
        let mut chain = SecretChain::create(file, secret, &seed, &request).unwrap();
        assert_eq!(chain.count(), 1);
        for i in 0..69 {
            let next = seed.auto_advance().unwrap();
            let request = random_request();
            chain.commit(&next, &request).unwrap();
            assert_eq!(chain.count(), i + 2);
            seed.commit(next);
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
        let secret = random_secret().unwrap();
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
        let request = random_request();
        let chain_secret = store.derive_secret(&chain_hash);
        assert_eq!(
            chain_secret,
            keyed_hash(secret.as_bytes(), chain_hash.as_bytes())
        );
        MutSecretBlock::new(&mut buf, &seed, &request).finalize();
        encrypt_in_place(&mut buf, &chain_secret, 0);
        store.remove_chain_file(&chain_hash).unwrap();
        let mut file = create_for_append(&filename).unwrap();
        file.write_all(&buf).unwrap();
        let chain = store.open_chain(&chain_hash).unwrap();
        assert_eq!(chain.tail().seed, seed);
    }

    #[test]
    fn test_store_create_chain() {
        let dir = TempDir::new().unwrap();
        let secret = random_hash();
        let store = SecretChainStore::new(dir.path(), secret);
        let chain_hash = random_hash();
        let seed = Seed::auto_create().unwrap();
        let request = random_request();
        let chain = store.create_chain(&chain_hash, &seed, &request).unwrap();
        assert_eq!(chain.tail().seed, seed);
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
