//! Read and write secret blocks in a chain.

use crate::always::*;
use crate::fsutil::{create_for_append, open_for_append, read_retry, secret_chain_filename};
use crate::{Hash, Secret, SecretBlock, SecretBlockError, SecretBlockState};
use argon2::Argon2;
use std::fs::{File, remove_file};
use std::io;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Secret chain header.
#[derive(Debug, PartialEq, Eq)]
pub struct SecretChainHeader {
    hash: Hash,
    salt: Secret,
}

impl SecretChainHeader {
    /// Create new header
    pub fn create(salt: Secret) -> Self {
        let hash = Hash::compute(salt.as_bytes());
        Self { hash, salt }
    }

    /// Load header from buffer
    pub fn from_buf(buf: &[u8]) -> Result<Self, SecretBlockError> {
        assert_eq!(buf.len(), SECRET_CHAIN_HEADER);
        let hash = Hash::from_slice(&buf[0..DIGEST]).unwrap();
        let salt = Secret::from_slice(&buf[DIGEST..SECRET_CHAIN_HEADER]).unwrap();
        let computed = Hash::compute(salt.as_bytes());
        if hash != computed {
            Err(SecretBlockError::ChainHeader)
        } else {
            Ok(Self { hash, salt })
        }
    }

    /// Write header to buffer
    pub fn write_to_buf(&self, buf: &mut [u8]) {
        assert_eq!(buf.len(), SECRET_CHAIN_HEADER);
        buf[0..DIGEST].copy_from_slice(self.hash.as_bytes());
        buf[DIGEST..SECRET_CHAIN_HEADER].copy_from_slice(self.salt.as_bytes());
    }

    /// Build buffer for writing to disk.
    pub fn into_buf(self) -> [u8; SECRET_CHAIN_HEADER] {
        let mut buf = [0; SECRET_CHAIN_HEADER];
        self.write_to_buf(&mut buf);
        buf
    }

    /// Derive the chain secret using Argon2.
    pub fn derive_chain_secret(&self, chain_hash: &Hash, password: &[u8]) -> Secret {
        // In case the salt and password get reused between chains, we first domain-ify the salt by
        // mixing it with the chain_hash. The chain_hash should be unique.
        let spice = self.salt.mix_with_hash(chain_hash);
        let mut secret = [0; SECRET];
        Argon2::default()
            .hash_password_into(password, spice.as_bytes(), &mut secret)
            .unwrap();
        Secret::from_bytes(secret)
    }
}

/// Save secret chain to non-volatile storage (encrypted and authenticated).
pub struct SecretChain {
    file: File,
    buf: Vec<u8>,
    pub(crate) chain_secret: Secret,
    first_block_hash: Hash,
    tail: SecretBlockState,
}

impl SecretChain {
    /// Create a new secret chain.
    pub fn create(
        mut file: File,
        mut buf: Vec<u8>,
        chain_header: SecretChainHeader,
        chain_secret: Secret,
        block_hash: &Hash,
    ) -> io::Result<Self> {
        assert_eq!(buf.len(), SECRET_BLOCK_AEAD);
        file.write_all(&chain_header.into_buf())?;
        file.write_all(&buf)?;
        let block = SecretBlock::new(&mut buf);
        let tail = block
            .from_hash_at_index(&chain_secret, block_hash, 0)
            .unwrap();
        let first_block_hash = tail.block_hash;
        Ok(Self {
            file,
            buf,
            chain_secret,
            first_block_hash,
            tail,
        })
    }

    /// Open and fully validate a secret chain.
    pub fn open(file: File, chain_hash: &Hash, password: &[u8]) -> io::Result<Self> {
        let mut file = BufReader::with_capacity(SECRET_BLOCK_AEAD_READ_BUF, file);
        file.rewind()?;
        let mut buf = vec![0; SECRET_BLOCK_AEAD];

        // Read the header
        buf.resize(SECRET_CHAIN_HEADER, 0);
        file.read_exact(&mut buf)?;
        let header = match SecretChainHeader::from_buf(&buf) {
            Ok(header) => header,
            Err(err) => return Err(err.to_io_error()),
        };
        let chain_secret = header.derive_chain_secret(chain_hash, password);

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
                buf.resize(SECRET_BLOCK_AEAD, 0);
                let read = read_retry(&mut file, &mut buf)?;
                if read < buf.len() {
                    let mut file = file.into_inner();
                    if read > 0 {
                        // Partially written block that should be truncated
                        let length = SECRET_CHAIN_HEADER as u64
                            + (tail.block_index + 1) * SECRET_BLOCK_AEAD as u64;
                        file.set_len(length)?;
                        file.seek(SeekFrom::End(0))?;
                    }
                    return Ok(Self {
                        file,
                        buf,
                        chain_secret,
                        first_block_hash,
                        tail,
                    });
                } else {
                    assert_eq!(read, buf.len());
                    let block = SecretBlock::new(&mut buf);
                    match block.from_previous(&chain_secret, &tail) {
                        Ok(state) => state,
                        Err(err) => return Err(err.to_io_error()),
                    }
                }
            };
        }
    }

    /// Exposes internal secret block buffer as mutable bytes.
    pub fn as_mut_buf(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }

    /// Number of blocks in this secret chain.
    pub fn count(&self) -> u64 {
        self.tail.block_index + 1
    }

    /// The [SecretBlockState] of the latest block in this secret chain.
    pub fn tail(&self) -> &SecretBlockState {
        &self.tail
    }

    /// Append secret block that has been built up in the internal buffer.
    pub fn append(&mut self, block_hash: &Hash) -> io::Result<()> {
        self.file.write_all(&self.buf)?;
        self.tail = {
            let block = SecretBlock::new(&mut self.buf);
            block.from_previous(&self.chain_secret, &self.tail).unwrap()
        };
        assert_eq!(&self.tail.block_hash, block_hash);
        Ok(())
    }

    /// Iterate through secret blocks in this secret chain.
    pub fn iter(&self) -> SecretChainIter {
        SecretChainIter::new(
            self.file.try_clone().unwrap(),
            self.chain_secret.clone(),
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
    secret: Secret,
    count: u64,
    first_block_hash: Hash,
    tail: Option<SecretBlockState>,
    buf: Vec<u8>,
}

impl SecretChainIter {
    fn new(file: File, secret: Secret, count: u64, first_block_hash: Hash) -> Self {
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
            tail.block_index + 1
        } else {
            0
        }
    }

    fn next_inner(&mut self) -> io::Result<SecretBlockState> {
        if self.tail.is_none() {
            // Rewind to the start of the first block (end of header)
            self.file
                .seek(SeekFrom::Start(SECRET_CHAIN_HEADER as u64))?;
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
                self.tail = Some(state.clone());
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
}

impl SecretChainStore {
    /// Creates a new place for your super secret chains.
    ///
    /// This has no side effects, performs no file system operations.
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    /// Create a new secret chain.
    pub fn create_chain(
        &self,
        buf: Vec<u8>,
        chain_header: SecretChainHeader,
        chain_secret: Secret,
        chain_hash: &Hash,
        block_hash: &Hash,
    ) -> io::Result<SecretChain> {
        let file = self.create_chain_file(chain_hash)?;
        SecretChain::create(file, buf, chain_header, chain_secret, block_hash)
    }

    /// Open secret chain file identified by its public `chain_hash`.
    pub fn open_chain(&self, chain_hash: &Hash, password: &[u8]) -> io::Result<SecretChain> {
        let file = self.open_chain_file(chain_hash)?;
        SecretChain::open(file, chain_hash, password)
    }

    /// List chains in this secret chain store.
    pub fn list_chains(&self) -> io::Result<Vec<Hash>> {
        let mut list = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            if let Some(osname) = entry.path().file_name() {
                if let Some(name) = osname.to_str() {
                    if name.len() == Z32DIGEST + 7 && &name[Z32DIGEST..] == ".secret" {
                        if let Ok(hash) = Hash::from_z32(&name.as_bytes()[0..Z32DIGEST]) {
                            list.push(hash);
                        }
                    }
                }
            }
        }
        list.sort();
        Ok(list)
    }

    /// Path of secret chain file identified by its public `chain_hash`.
    pub fn chain_filename(&self, chain_hash: &Hash) -> PathBuf {
        secret_chain_filename(&self.dir, chain_hash)
    }

    /// Open the existing secret chain file identified by its public `chain_hash`.
    pub fn open_chain_file(&self, chain_hash: &Hash) -> io::Result<File> {
        let filename = self.chain_filename(chain_hash);
        open_for_append(&filename)
    }

    /// Create a new secret chain file identified by its public `chain_hash`.
    pub fn create_chain_file(&self, chain_hash: &Hash) -> io::Result<File> {
        let filename = self.chain_filename(chain_hash);
        create_for_append(&filename)
    }

    /// Remove the secret chain file identified by its public `chain_hash`.
    pub fn remove_chain_file(&self, chain_hash: &Hash) -> io::Result<()> {
        let filename = self.chain_filename(chain_hash);
        remove_file(&filename)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhelpers::{BitFlipper, random_hash, random_payload};
    use crate::{MutSecretBlock, Seed};
    use getrandom;
    use std::collections::HashSet;
    use std::io::Seek;
    use tempfile::{TempDir, tempfile};

    fn short_password() -> [u8; 5] {
        let mut buf = [0; 5];
        getrandom::fill(&mut buf).unwrap();
        buf
    }

    #[test]
    fn test_secret_chain_header() {
        let salt = Secret::generate().unwrap();
        let header = SecretChainHeader::create(salt.clone());
        assert_eq!(header.hash, Hash::compute(salt.as_bytes()));
        assert_eq!(header.salt, salt);
        let mut buf = [0; SECRET_CHAIN_HEADER];
        header.write_to_buf(&mut buf);

        let header2 = SecretChainHeader::from_buf(&buf).unwrap();
        assert_eq!(header2.hash, header.hash);
        assert_eq!(header2.salt, salt);
        assert_eq!(header2, header);

        for bad_buf in BitFlipper::new(&buf) {
            assert_eq!(
                SecretChainHeader::from_buf(&bad_buf),
                Err(SecretBlockError::ChainHeader)
            );
        }

        // Test PBKDF
        let mut hset = HashSet::new();
        assert!(hset.insert(salt.clone()));
        let passwords: [&[u8; 21]; 3] = [
            b"Super Bader Passwords",
            b"Yeah don't use this!!",
            b"whatever, same length",
        ];
        for pw in passwords {
            for _ in 0..11 {
                let chain_hash = random_hash();
                let chain_secret = header.derive_chain_secret(&chain_hash, pw);
                assert!(hset.insert(chain_secret));
            }
        }
        assert_eq!(hset.len(), passwords.len() * 11 + 1);
    }

    #[test]
    fn test_chain_create_open() {
        let mut buf = vec![0; SECRET_BLOCK];
        let payload = random_payload();
        let mut block = MutSecretBlock::new(&mut buf, &payload);

        let seed = Seed::generate().unwrap();
        block.set_seed(&seed);

        let salt = Secret::generate().unwrap();
        let header = SecretChainHeader::create(salt);
        let chain_hash = random_hash();
        let password = short_password();

        let chain_secret = header.derive_chain_secret(&chain_hash, &password);
        let block_hash = block.finalize(&chain_secret);

        let mut buf2 = buf.clone();
        let state = SecretBlock::new(&mut buf2)
            .from_hash_at_index(&chain_secret, &block_hash, 0)
            .unwrap();

        let mut file = tempfile().unwrap();
        let chain = SecretChain::create(
            file.try_clone().unwrap(),
            buf,
            header,
            chain_secret.clone(),
            &block_hash,
        )
        .unwrap();
        assert_eq!(chain.tail(), &state);

        // Write a single extra byte at end. If truncation isn't done correctly when reopening the chain
        // the chain will be in an invalid state after the next block is written, and validation will fail
        // with SecretBlockError::Decryption
        file.write_all(b"0").unwrap();

        // Reopen chain, test SecretChain::open()
        let mut chain =
            SecretChain::open(file.try_clone().unwrap(), &chain_hash, &password).unwrap();
        assert_eq!(chain.tail(), &state);

        // Sign another
        let payload = random_payload();
        let mut block = MutSecretBlock::new(chain.as_mut_buf(), &payload);
        block.set_previous(&state);
        let next_seed = seed.advance().unwrap();
        block.set_seed(&next_seed);
        let block_hash2 = block.finalize(&chain_secret);
        chain.append(&block_hash2).unwrap();
        let state2 = chain.tail().clone();

        // Reopen chain, test SecretChain::open()
        let chain = SecretChain::open(file.try_clone().unwrap(), &chain_hash, &password).unwrap();
        assert_eq!(chain.tail(), &state2);

        // Test bit flips in password
        for bad_password in BitFlipper::new(&password) {
            assert!(
                SecretChain::open(file.try_clone().unwrap(), &chain_hash, &bad_password).is_err()
            );
        }
    }

    #[test]
    fn test_chain_open() {
        let mut file = tempfile().unwrap();
        let chain_hash = random_hash();
        let password = random_hash();

        // Empty file
        assert!(
            SecretChain::open(file.try_clone().unwrap(), &chain_hash, password.as_bytes()).is_err()
        );

        // A secret aead block full of random data
        let mut buf = vec![0; SECRET_BLOCK_AEAD];
        getrandom::fill(&mut buf).unwrap();
        file.write_all(&buf).unwrap();
        file.rewind().unwrap();
        assert!(SecretChain::open(file, &chain_hash, password.as_bytes()).is_err());
    }

    #[test]
    fn test_chain_append() {
        let mut buf = vec![0; SECRET_BLOCK];
        let payload = random_payload();
        let mut block = MutSecretBlock::new(&mut buf, &payload);

        let mut seed = Seed::generate().unwrap();
        block.set_seed(&seed);

        let salt = Secret::generate().unwrap();
        let header = SecretChainHeader::create(salt);
        let chain_hash = random_hash();
        let password = random_hash();
        let chain_secret = header.derive_chain_secret(&chain_hash, password.as_bytes());
        let block_hash = block.finalize(&chain_secret);

        let mut file = tempfile().unwrap();
        let mut chain = SecretChain::create(
            file.try_clone().unwrap(),
            buf,
            header,
            chain_secret.clone(),
            &block_hash,
        )
        .unwrap();
        assert_eq!(chain.count(), 1);
        for i in 2..69 {
            seed = seed.advance().unwrap();
            let payload = random_payload();
            let tail = chain.tail().clone();
            let mut block = MutSecretBlock::new(chain.as_mut_buf(), &payload);
            block.set_previous(&tail);
            block.set_seed(&seed);
            let block_hash = block.finalize(&chain_secret);
            chain.append(&block_hash).unwrap();
            assert_eq!(chain.count(), i);
        }
        file.rewind().unwrap();
        SecretChain::open(file, &chain_hash, password.as_bytes()).unwrap();
    }

    #[test]
    fn test_store_list_chains() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let store = SecretChainStore::new(tmpdir.path());
        assert_eq!(store.list_chains().unwrap(), []);

        let hash = random_hash();
        let mut name = tmpdir.path().join(&hash.to_z32_string());
        create_for_append(&name).unwrap();
        assert_eq!(store.list_chains().unwrap(), []); // Public chain files should be ignored

        name.set_extension("secret");
        create_for_append(&name).unwrap();
        assert_eq!(store.list_chains().unwrap(), [hash]);

        create_for_append(&tmpdir.path().join("foo")).unwrap();
        create_for_append(&tmpdir.path().join("bar")).unwrap();
        assert_eq!(store.list_chains().unwrap(), [hash]);

        let hash2 = random_hash();
        let mut name2 = tmpdir.path().join(&hash2.to_z32_string());
        create_for_append(&name2).unwrap();
        assert_eq!(store.list_chains().unwrap(), [hash]); // Public chain files should be ignored

        name2.set_extension("secret");
        create_for_append(&name2).unwrap();
        let mut expected = [hash, hash2];
        expected.sort();
        assert_eq!(store.list_chains().unwrap(), expected);
    }

    #[test]
    fn test_store_chain_filename() {
        let dir = PathBuf::from("/nope");
        let store = SecretChainStore::new(dir.as_path());
        let chain_hash = Hash::from_bytes([69; DIGEST]);
        assert_eq!(
            store.chain_filename(&chain_hash),
            PathBuf::from(
                "/nope/CP6OELE9CP6OELE9CP6OELE9CP6OELE9CP6OELE9CP6OELE9CP6OELE9CP6OELE9.secret"
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
        let store = SecretChainStore::new(dir.path());
        let chain_hash = random_hash();
        assert!(store.open_chain(&chain_hash, b"Bad Password").is_err());
        let filename = store.chain_filename(&chain_hash);

        let mut file = create_for_append(&filename).unwrap();
        let mut buf = [0; SECRET_CHAIN_HEADER + SECRET_BLOCK_AEAD];
        getrandom::fill(&mut buf).unwrap();
        file.write_all(&buf).unwrap();
        file.rewind().unwrap();
        assert!(store.open_chain(&chain_hash, b"Bad Password").is_err()); // Not valid ChaCha20Poly1305 content
    }

    #[test]
    fn test_store_create_chain_open() {
        let salt = Secret::generate().unwrap();
        let header = SecretChainHeader::create(salt);
        let chain_hash = random_hash();
        let password = random_hash();
        let chain_secret = header.derive_chain_secret(&chain_hash, password.as_bytes());

        let seed = Seed::generate().unwrap();
        let payload = random_payload();

        let mut buf = vec![0; SECRET_BLOCK];
        let mut block = MutSecretBlock::new(&mut buf, &payload);
        block.set_seed(&seed);
        let block_hash = block.finalize(&chain_secret);

        let dir = TempDir::new().unwrap();
        let store = SecretChainStore::new(dir.path());
        let chain = store
            .create_chain(buf, header, chain_secret, &chain_hash, &block_hash)
            .unwrap();

        let state = chain.tail().clone();
        assert_eq!(state.payload, payload);
        assert_eq!(state.seed, seed);

        // Reopen the chain
        let chain = store.open_chain(&chain_hash, password.as_bytes()).unwrap();
        assert_eq!(chain.tail(), &state);
    }

    #[test]
    fn test_store_remove_file() {
        let dir = TempDir::new().unwrap();
        let store = SecretChainStore::new(dir.path());
        let chain_hash = random_hash();
        assert!(store.remove_chain_file(&chain_hash).is_err());
        let filename = store.chain_filename(&chain_hash);
        create_for_append(&filename).unwrap();
        assert!(store.remove_chain_file(&chain_hash).is_ok());
        assert!(store.remove_chain_file(&chain_hash).is_err());
    }
}
