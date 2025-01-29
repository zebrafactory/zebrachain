//! Read and write secret blocks in a chain.

use crate::always::*;
use crate::block::SigningRequest;
use crate::fsutil::{build_filename, create_for_append, open_for_append};
use crate::secretblock::{MutSecretBlock, SecretBlock};
use crate::secretseed::{derive, Secret, Seed};
use blake3::{keyed_hash, Hash};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum StorageError {
    Bad,
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

    pub fn open(mut file: File, secret: Secret) -> io::Result<Self> {
        let mut buf = vec![0; SECRET_BLOCK_AEAD];
        file.read_exact(&mut buf[..])?;
        decrypt_in_place(&mut buf, &secret, 0).unwrap(); // FIXME
        let mut tail = match SecretBlock::open(&buf[..]) {
            Ok(block) => block,
            Err(err) => return Err(err.to_io_error()),
        };
        buf.resize(SECRET_BLOCK_AEAD, 0);
        while file.read_exact(&mut buf[..]).is_ok() {
            decrypt_in_place(&mut buf, &secret, tail.index + 1).unwrap(); // FIXME
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

    fn read_block(&self, buf: &mut Vec<u8>, index: u64) -> io::Result<()> {
        buf.resize(SECRET_BLOCK_AEAD, 0);
        let offset = index * SECRET_BLOCK_AEAD as u64;
        self.file.read_exact_at(&mut buf[..], offset)?;
        decrypt_in_place(buf, &self.secret, index).unwrap(); // FIXME
        Ok(())
    }

    pub fn tail(&self) -> &SecretBlock {
        &self.tail
    }

    pub fn commit(&mut self, seed: &Seed, request: &SigningRequest) -> io::Result<()> {
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
        SecretChainIter::new(self)
    }
}

impl<'a> IntoIterator for &'a SecretChain {
    type Item = io::Result<SecretBlock>;
    type IntoIter = SecretChainIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct SecretChainIter<'a> {
    secretchain: &'a SecretChain,
    tail: Option<SecretBlock>,
}

impl<'a> SecretChainIter<'a> {
    pub fn new(secretchain: &'a SecretChain) -> Self {
        Self {
            secretchain,
            tail: None,
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
        assert!(self.index() < self.secretchain.count());
        let mut buf = vec![0; SECRET_BLOCK_AEAD];
        self.secretchain.read_block(&mut buf, self.index())?;
        let result = if let Some(tail) = self.tail.as_ref() {
            SecretBlock::from_previous(&buf[..], tail)
        } else {
            SecretBlock::open(&buf)
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

impl Iterator for SecretChainIter<'_> {
    type Item = io::Result<SecretBlock>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index() < self.secretchain.count() {
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

    pub fn open_chain(&self, chain_hash: &Hash) -> io::Result<SecretChain> {
        let filename = build_filename(&self.dir, chain_hash);
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
        let filename = build_filename(&self.dir, chain_hash);
        let file = create_for_append(&filename)?;
        let secret = self.derive_secret(chain_hash);
        SecretChain::create(file, secret, seed, request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secretseed::random_secret;
    use crate::testhelpers::{random_request, BitFlipper};
    use blake3::hash;
    use getrandom;
    use std::collections::HashSet;
    use std::io::Seek;
    use tempfile::tempfile;

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
        assert_eq!(seed, block.seed());
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
        SecretChain::open(file, secret).unwrap();
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
}
