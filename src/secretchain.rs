//! Manages chain of secrets.

use blake3::{keyed_hash, Hash, Hasher};
use std::fs::File;
use std::io::Result as IoResult;
use std::io::{Read, Seek, SeekFrom, Write};

/*
Steps to create a new chain:

1. Generate first 2 secrets in SecretChain
2. First secret generates the KeyPair that will sign the first block
3. Second secret generates the PubKey that will sign the *next* block (we just need pubkey hash)
4. Sign block

5. Write new secret in SecretChain, new Block in Chain
*/

static SECRET_CONTEXT: &str = "foo";
static NEXT_SECRET_CONTEXT: &str = "bar";

fn derive(context: &str, secret: &[u8]) -> Hash {
    let mut hasher = Hasher::new_derive_key(context);
    hasher.update(secret);
    hasher.finalize()
}

/// Stores secret and next_secret.
///
/// # Examples
///
/// ```
/// use zebrachain::secretchain::Seed;
/// let initial_entropy = [42; 32];
/// let new_entropy = [69; 32];
/// let seed = Seed::create(&initial_entropy);
/// let seed = seed.advance(&new_entropy);
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct Seed {
    pub secret: Hash,
    pub next_secret: Hash,
}

impl Seed {
    fn new(secret: Hash, next_secret: Hash) -> Self {
        if secret == next_secret {
            panic!("secret and next_secret cannot be equal");
        }
        Self {
            secret,
            next_secret,
        }
    }

    pub fn as_secret_bytes(&self) -> &[u8] {
        self.secret.as_bytes()
    }

    pub fn as_next_secret_bytes(&self) -> &[u8] {
        self.next_secret.as_bytes()
    }

    pub fn load(buf: &[u8; 64]) -> Self {
        let secret = Hash::from_bytes(buf[0..32].try_into().unwrap());
        let next_secret = Hash::from_bytes(buf[32..64].try_into().unwrap());
        Self::new(secret, next_secret)
    }

    pub fn create(initial_entropy: &[u8; 32]) -> Self {
        let secret = derive(SECRET_CONTEXT, initial_entropy);
        let next_secret = derive(NEXT_SECRET_CONTEXT, initial_entropy);
        Self::new(secret, next_secret)
    }

    pub fn advance(&self, new_entropy: &[u8; 32]) -> Self {
        let secret = self.next_secret;
        let next_secret = keyed_hash(self.next_secret.as_bytes(), new_entropy);
        Self::new(secret, next_secret)
    }
}

pub struct SecretChain {
    file: File,
    seed: Seed,
}

impl SecretChain {
    pub fn create(mut file: File, seed: Seed) -> IoResult<Self> {
        file.write_all(seed.as_secret_bytes())?;
        file.write_all(seed.as_next_secret_bytes())?;
        Ok(Self { file, seed })
    }

    pub fn open(mut file: File) -> IoResult<Self> {
        file.seek(SeekFrom::End(-64))?;
        let mut buf = [0; 64];
        file.read_exact(&mut buf)?;
        let seed = Seed::load(&buf);
        Ok(Self { file, seed })
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
    fn test_seed_new() {
        let secret = hash(&[42; 32]);
        let next_secret = hash(&[69; 32]);
        let seed = Seed::new(secret, next_secret);
        assert_eq!(seed.secret, hash(&[42; 32]));
        assert_eq!(seed.next_secret, hash(&[69; 32]));
    }

    #[test]
    #[should_panic(expected = "secret and next_secret cannot be equal")]
    fn test_seed_new_panic() {
        let secret = hash(&[42; 32]);
        let next_secret = hash(&[42; 32]);
        let seed = Seed::new(secret, next_secret);
    }

    #[test]
    fn test_seed_load() {
        let mut buf: [u8; 64] = [0; 64];
        buf[0..32].copy_from_slice(&[42; 32]);
        buf[32..64].copy_from_slice(&[69; 32]);
        let seed = Seed::load(&buf);
        assert_eq!(seed.secret.as_bytes(), &[42; 32]);
        assert_eq!(seed.next_secret.as_bytes(), &[69; 32]);
    }

    #[test]
    #[should_panic(expected = "secret and next_secret cannot be equal")]
    fn test_seed_load_panic() {
        let buf = [42; 64];
        let seed = Seed::load(&buf);
    }

    #[test]
    fn test_seed_create() {
        let mut hset: HashSet<Hash> = HashSet::new();
        for i in 0..=255 {
            let entropy = [i; 32];
            let seed = Seed::create(&entropy);
            assert!(hset.insert(seed.secret));
            assert!(hset.insert(seed.next_secret));
        }
        assert_eq!(hset.len(), 512);
    }

    #[test]
    fn test_seed_advance() {
        let count = 10000;
        let entropy = [69; 32];
        let mut seed = Seed::create(&entropy);
        let mut hset: HashSet<Hash> = HashSet::new();
        assert!(hset.insert(seed.secret));
        assert!(hset.insert(seed.next_secret));
        for _ in 0..count {
            seed = seed.advance(&entropy);
            assert!(!hset.insert(seed.secret)); // Should already be contained
            assert!(hset.insert(seed.next_secret));
        }
        assert_eq!(hset.len(), count + 2);
    }

    #[test]
    fn test_sc_create() {
        let file = tempfile().unwrap();
        let seed = Seed::create(&[42; 32]);
        let result = SecretChain::create(file, seed.clone());
        assert!(result.is_ok());
        let mut file = result.unwrap().into_file();
        file.rewind().unwrap();
        let mut buf = [0; 64];
        file.read_exact(&mut buf).unwrap();
        let seed2 = Seed::load(&buf);
        assert_eq!(seed, seed2);
    }

    #[test]
    fn test_sc_open() {
        let file = tempfile().unwrap();
        assert!(SecretChain::open(file).is_err());

        let mut file = tempfile().unwrap();
        file.write_all(&[42; 32]).unwrap();
        assert!(SecretChain::open(file).is_err());

        let mut file = tempfile().unwrap();
        file.write_all(&[42; 32]).unwrap();
        file.write_all(&[69; 32]).unwrap();
        assert!(SecretChain::open(file).is_ok());
    }
}
