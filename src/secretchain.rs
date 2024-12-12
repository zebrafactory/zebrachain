//! Manages chain of secrets.

use blake3::{keyed_hash, Hash, Hasher};
use std::fs::File;
use std::io::Result as IoResult;
use std::io::{Read, Write};

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
static SECRET_CHAIN_CONTEXT: &str = "win.zebrachain chain";

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
pub struct Seed {
    pub secret: Hash,
    pub next_secret: Hash,
}

impl Seed {
    pub fn new(secret: Hash, next_secret: Hash) -> Self {
        if secret == next_secret {
            panic!("secret and next_secret cannot be equal");
        }
        Self {
            secret,
            next_secret,
        }
    }

    pub fn create(initial_entropy: &[u8; 32]) -> Self {
        let secret = derive(SECRET_CONTEXT, initial_entropy);
        let next_secret = derive(NEXT_SECRET_CONTEXT, initial_entropy);
        Self::new(secret, next_secret)
    }

    pub fn advance(self, new_entropy: &[u8; 32]) -> Self {
        let secret = self.next_secret;
        let next_secret = keyed_hash(self.next_secret.as_bytes(), new_entropy);
        Self::new(secret, next_secret)
    }
}

pub struct SecretChain {
    file: File,
    pub key: Hash,
    pub next_key: Option<Hash>,
}

impl SecretChain {
    pub fn new(file: File, initial_entropy: &[u8; 32]) -> Self {
        let mut h = Hasher::new_derive_key(SECRET_CHAIN_CONTEXT);
        h.update(initial_entropy);
        Self {
            file,
            key: h.finalize(),
            next_key: None,
        }
    }

    pub fn advance(&mut self, new_entropy: &[u8; 32]) {
        if self.next_key.is_some() {
            panic!("Cannot call Chain.advance() when next_key is Some");
        }
        self.next_key = Some(keyed_hash(self.key.as_bytes(), new_entropy));
    }

    pub fn unadvance(&mut self) {
        if self.next_key.take().is_none() {
            panic!("Cannot call Chain.unadvance() when next_key is None");
        }
    }

    pub fn commit(&mut self) -> IoResult<()> {
        let key = self.next_key.take();
        if key.is_none() {
            panic!("Cannot call Chain.commit() when next_key is None");
        }
        self.key = key.unwrap();
        self.file.write_all(self.key.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake3::hash;
    use std::collections::HashSet;
    use tempfile::tempfile;

    fn new_sc() -> SecretChain {
        let file = tempfile().unwrap();
        let key = [69; 32];
        SecretChain::new(file, &key)
    }

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
    fn test_sc_new() {
        let file = tempfile().unwrap();
        let key = [69; 32];
        let sc = SecretChain::new(file, &key);
        assert_eq!(
            sc.key,
            Hash::from_hex("1f90fc1e2ad76220f1c4069018e0b48ecba090379aa6dc969b2d92a67fb05e49")
                .unwrap()
        );
    }

    #[test]
    #[should_panic(expected = "Cannot call Chain.advance() when next_key is Some")]
    fn test_sc_advance_panic() {
        let mut sc = new_sc();
        sc.advance(&[42; 32]);
        sc.advance(&[77; 32]);
    }

    #[test]
    #[should_panic(expected = "Cannot call Chain.unadvance() when next_key is None")]
    fn test_sc_unadvance_panic() {
        let mut sc = new_sc();
        sc.unadvance();
    }

    #[test]
    #[should_panic(expected = "Cannot call Chain.commit() when next_key is None")]
    fn test_sc_commit_panic() {
        let mut sc = new_sc();
        sc.commit().unwrap();
    }

    #[test]
    fn test_sc_unadvance() {
        let mut sc = new_sc();
        sc.advance(&[42; 32]);
        assert!(sc.next_key.is_some());
        sc.unadvance();
        assert!(sc.next_key.is_none());
    }

    #[test]
    fn test_sc_commit() {
        let mut sc = new_sc();
        sc.advance(&[42; 32]);
        assert!(sc.next_key.is_some());
        assert!(sc.commit().is_ok());
        assert!(sc.next_key.is_none());
    }
}
