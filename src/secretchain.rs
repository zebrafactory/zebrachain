use blake3::{keyed_hash, Hash};
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

pub struct SecretChain {
    file: File,
    pub key: [u8; 32],
    pub next_key: Option<Hash>,
}

impl SecretChain {
    pub fn new(file: File, key: [u8; 32]) -> Self {
        Self {
            file,
            key,
            next_key: None,
        }
    }

    pub fn advance(&mut self, new_entropy: &[u8; 32]) {
        if self.next_key.is_some() {
            panic!("Cannot call Chain.advance() when next_key already has a value");
        }
        self.next_key = Some(keyed_hash(&self.key, new_entropy));
    }

    pub fn unadvance(&mut self) {
        if self.next_key.take().is_none() {
            panic!("Cannot call Chain.unadvance() next_key is None");
        }
    }

    pub fn commit(&mut self) -> IoResult<()> {
        let key = self.next_key.take();
        if key.is_none() {
            panic!("Cannot call Chain.commit() next_key is None");
        }
        self.key.copy_from_slice(key.unwrap().as_bytes());
        self.file.write_all(&self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempfile;

    fn new_sc() -> SecretChain {
        let file = tempfile().unwrap();
        let key = [69; 32];
        SecretChain::new(file, key)
    }

    #[test]
    fn test_sc_new() {
        let file = tempfile().unwrap();
        let key = [69; 32];
        let sc = SecretChain::new(file, key);
        assert_eq!(sc.key, [69; 32]);
    }

    #[test]
    #[should_panic(expected = "Cannot call Chain.advance() when next_key already has a value")]
    fn test_sc_advance_panic() {
        let mut sc = new_sc();
        sc.advance(&[42; 32]);
        sc.advance(&[77; 32]);
    }

    #[test]
    #[should_panic(expected = "Cannot call Chain.unadvance() next_key is None")]
    fn test_sc_unadvance_panic() {
        let mut sc = new_sc();
        sc.unadvance();
    }

    #[test]
    #[should_panic(expected = "Cannot call Chain.commit() next_key is None")]
    fn test_sc_commit_panic() {
        let mut sc = new_sc();
        sc.commit();
    }
}
