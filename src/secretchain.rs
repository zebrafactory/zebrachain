//! Read and write secret blocks in a chain.

use crate::secretseed::Seed;
use std::fs::File;
use std::io::Result as IoResult;
use std::io::{Read, Seek, SeekFrom, Write};

/// Save secret chain to non-volitile storage.
///
/// This is pure crap currently.  We need validation and encryption of this.
///
/// But remember an import use case for ZebraChain is Hardware Security Modules
/// that *never* write any secrets to non-volitle storage.  Always on, only in
/// memory.
///
/// Good idea: when we are saving a secret chain, we should include the
/// state_hash and timestamp in the secret block... that way the public block
/// can be recreating from the secret chain if the public block doesn't make it
/// to non-volitile storage.
pub struct SecretStore {
    file: File,
    seed: Seed,
}

impl SecretStore {
    pub fn create(mut file: File, seed: Seed) -> IoResult<Self> {
        file.write_all(seed.secret.as_bytes())?;
        file.write_all(seed.next_secret.as_bytes())?;
        Ok(Self { file, seed })
    }

    pub fn open(mut file: File) -> IoResult<Self> {
        file.seek(SeekFrom::End(-64))?;
        let mut buf = [0; 64];
        file.read_exact(&mut buf)?;
        let seed = Seed::load(&buf)?;
        Ok(Self { file, seed })
    }

    pub fn current_seed(&self) -> Seed {
        self.seed.clone()
    }

    pub fn advance(&self, new_entropy: &[u8; 32]) -> Seed {
        self.seed.advance(new_entropy)
    }

    pub fn commit(&mut self, seed: Seed) -> IoResult<()> {
        self.file.write_all(seed.next_secret.as_bytes())?;
        self.seed.commit(seed);
        Ok(())
    }

    pub fn into_file(self) -> File {
        self.file
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake3::hash;
    use std::collections::HashSet;
    use tempfile::tempfile;

    #[test]
    fn test_store_create() {
        let file = tempfile().unwrap();
        let seed = Seed::create(&[42; 32]);
        let result = SecretStore::create(file, seed.clone());
        assert!(result.is_ok());
        let mut file = result.unwrap().into_file();
        file.rewind().unwrap();
        let mut buf = [0; 64];
        file.read_exact(&mut buf).unwrap();
        let seed2 = Seed::load(&buf).unwrap();
        assert_eq!(seed, seed2);
    }

    #[test]
    fn test_store_open() {
        let file = tempfile().unwrap();
        assert!(SecretStore::open(file).is_err());

        let mut file = tempfile().unwrap();
        file.write_all(&[42; 32]).unwrap();
        assert!(SecretStore::open(file).is_err());

        let mut file = tempfile().unwrap();
        file.write_all(&[42; 32]).unwrap();
        file.write_all(&[69; 32]).unwrap();
        assert!(SecretStore::open(file).is_ok());
    }

    #[test]
    fn test_store_advance_and_commit() {
        let count = 1000;
        let entropy = [69; 32];
        let file = tempfile().unwrap();
        let seed = Seed::create(&entropy);
        let mut store = SecretStore::create(file, seed.clone()).unwrap();
        for _ in 0..count {
            let next = store.advance(&entropy);
            assert!(store.commit(next).is_ok());
        }
        let last = store.current_seed();
        let file = store.into_file();
        let store = SecretStore::open(file).unwrap();
        assert_eq!(last, store.current_seed());
    }

    #[test]
    #[should_panic(expected = "cannot commit out of sequence seed")]
    fn test_store_commit_panic() {
        let entropy = &[69; 32];
        let file = tempfile().unwrap();
        let seed = Seed::create(&entropy);
        let mut store = SecretStore::create(file, seed).unwrap();
        let next = store.advance(&entropy);
        let next_next = next.advance(&entropy);
        store.commit(next_next);
    }
}
