//! Read and write secret blocks in a chain.

use crate::always::*;
use crate::block::SigningRequest;
use crate::fsutil::{build_filename, create_for_append, open_for_append};
use crate::secretblock::{MutSecretBlock, SecretBlock};
use crate::secretseed::{derive, random_secret, Secret, Seed};
use blake3::{keyed_hash, Hash};
use chacha20poly1305::{
    aead::{AeadCore, AeadInPlace, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

const SECRET_BLOCK_AEAD: usize = SECRET_BLOCK + 16;

/*
We should likewise do entropy accumulation when creating the nonce for each block. The hash of the
latest block is a great accumulator.
*/

/// Save secret chain to non-volitile storage.
///
/// The SecretBlock and SecretChain are decent now, but we still aren't encrypting this. So still
/// kinda crappy.
///
/// But remember an import use case for ZebraChain is Hardware Security Modules that *never* write
/// any secrets to non-volitle storage.  Always on, only in memory.
pub struct SecretChain {
    file: File,
    tail: SecretBlock,
    count: u64,
    secret: Secret,
    buf: Vec<u8>,
}

impl SecretChain {
    fn new(file: File, tail: SecretBlock, count: u64) -> Self {
        Self {
            file,
            tail,
            count,
            secret: Secret::from_bytes([69; 32]),
            buf: Vec::with_capacity(SECRET_BLOCK_AEAD),
        }
    }

    pub fn create(mut file: File, seed: &Seed, request: &SigningRequest) -> io::Result<Self> {
        let mut buf = [0; SECRET_BLOCK];
        let block = MutSecretBlock::new(&mut buf, seed, request);
        let block = block.finalize();
        file.write_all(&buf)?;
        Ok(Self::new(file, block, 1))
    }

    pub fn open(mut file: File) -> io::Result<Self> {
        let mut buf = [0; SECRET_BLOCK];
        file.read_exact(&mut buf)?;
        let mut tail = match SecretBlock::open(&buf) {
            Ok(block) => block,
            Err(err) => return Err(err.to_io_error()),
        };
        let mut count = 1;
        while file.read_exact(&mut buf).is_ok() {
            tail = match SecretBlock::from_previous(&buf, &tail) {
                Ok(block) => block,
                Err(err) => return Err(err.to_io_error()),
            };
            count += 1;
        }
        Ok(Self::new(file, tail, count))
    }

    // Use a unique key and nonce for each block
    fn derive_block_secrets(&self, index: u64) -> (Key, Nonce) {
        let root = keyed_hash(self.secret.as_bytes(), &index.to_le_bytes());
        let key = derive(STORAGE_KEY_CONTEXT, &root);
        let nonce = derive(STORAGE_NONCE_CONTEXT, &root);
        let key = Key::from_slice(&key.as_bytes()[..]);
        let nonce = Nonce::from_slice(&nonce.as_bytes()[0..12]);
        (*key, *nonce)
    }

    fn read_block(&self, buf: &mut [u8], index: u64) -> io::Result<()> {
        let offset = index * SECRET_BLOCK as u64;
        self.file.read_exact_at(buf, offset)
    }

    pub fn tail(&self) -> &SecretBlock {
        &self.tail
    }

    pub fn commit(&mut self, seed: &Seed, request: &SigningRequest) -> io::Result<()> {
        self.buf.resize(SECRET_BLOCK, 0);
        let mut block = MutSecretBlock::new(&mut self.buf[..], seed, request);
        block.set_previous(&self.tail);
        let block = block.finalize();
        let (key, nonce) = self.derive_block_secrets(self.count);
        let cipher = ChaCha20Poly1305::new(&key);
        self.file.write_all(&self.buf)?;
        cipher.encrypt_in_place(&nonce, b"", &mut self.buf).unwrap();
        assert_eq!(self.buf.len(), SECRET_BLOCK_AEAD);
        self.tail = block;
        self.count += 1;
        Ok(())
    }

    pub fn into_file(self) -> File {
        self.file
    }

    pub fn iter(&self) -> SecretChainIter {
        SecretChainIter::new(self, self.count)
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
    index: u64,
    count: u64,
    tail: Option<SecretBlock>,
}

impl<'a> SecretChainIter<'a> {
    pub fn new(secretchain: &'a SecretChain, count: u64) -> Self {
        if count == 0 {
            panic!("count cannot be 0");
        }
        Self {
            secretchain,
            index: 0,
            count,
            tail: None,
        }
    }

    fn next_inner(&mut self) -> io::Result<SecretBlock> {
        assert!(self.index < self.count);
        let mut buf = [0; SECRET_BLOCK];
        self.secretchain.read_block(&mut buf, self.index)?;
        self.index += 1;

        let result = if let Some(tail) = self.tail.as_ref() {
            SecretBlock::from_previous(&buf, tail)
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
        if self.index < self.count {
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
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            secret: Secret::from_bytes([69; 32]), // FIXME (to put it mildly)
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
        SecretChain::open(file)
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
        SecretChain::create(file, seed, request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::SigningRequest;
    use crate::testhelpers::random_hash;
    use std::io::Seek;
    use tempfile::tempfile;

    #[test]
    fn test_chacha20poly1305() {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&[69; 32]);
        assert_eq!(buf.len(), 32);
        cipher.encrypt_in_place(&nonce, b"", &mut buf).unwrap();
        assert_eq!(buf.len(), 48);
        cipher.decrypt_in_place(&nonce, b"", &mut buf).unwrap();
        assert_eq!(&buf, &[69; 32])
    }

    #[test]
    fn test_chain_create() {
        let file = tempfile().unwrap();
        let seed = Seed::create(&Hash::from_bytes([42; 32]));
        let request = SigningRequest::new(random_hash(), Hash::from_bytes([69; DIGEST]));
        let result = SecretChain::create(file, &seed, &request);
        assert!(result.is_ok());
        let mut file = result.unwrap().into_file();
        file.rewind().unwrap();
        let mut buf = [0; SECRET_BLOCK];
        file.read_exact(&mut buf).unwrap();
        let block = SecretBlock::open(&buf).unwrap();
        assert_eq!(seed, block.seed());
    }

    #[test]
    fn test_chain_open() {
        let mut file = tempfile().unwrap();
        assert!(SecretChain::open(file.try_clone().unwrap()).is_err());
        let mut buf = [0; SECRET_BLOCK];

        let seed = Seed::auto_create().unwrap();
        let request = SigningRequest::new(random_hash(), random_hash());
        let block = MutSecretBlock::new(&mut buf, &seed, &request);
        block.finalize();

        file.write_all(&buf).unwrap();
        file.rewind().unwrap();
        SecretChain::open(file).unwrap();
    }

    #[test]
    fn test_chain_advance_and_commit() {
        let entropy = Hash::from_bytes([69; 32]);
        let file = tempfile().unwrap();
        let mut seed = Seed::create(&entropy);
        let request = SigningRequest::new(
            Hash::from_bytes([69; DIGEST]),
            Hash::from_bytes([42; DIGEST]),
        );
        let mut chain = SecretChain::create(file, &seed, &request).unwrap();
        assert_eq!(chain.count, 1);
        for i in 0u8..=255 {
            let next = seed.advance(&entropy);
            let request = SigningRequest::new(random_hash(), Hash::from_bytes([i; DIGEST]));
            chain.commit(&next, &request).unwrap();
            assert_eq!(chain.count, i as u64 + 2);
            seed.commit(next);
        }
        let mut file = chain.into_file();
        file.rewind().unwrap();
        SecretChain::open(file).unwrap();
    }
}
