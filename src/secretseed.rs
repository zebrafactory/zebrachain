//! Entropy accumulating chain of secrets (in-memory).
//!
//! Note there is a lot of secret comparison in this module that relies on the constant time
//! comparison of [blake3::Hash] to be secure. Once the hash is configurable, we need to make sure
//! whatever abstraction we use likewise ensures constant time comparison.

use crate::always::*;
use blake3::{keyed_hash, Hash, Hasher};
use getrandom::getrandom;

pub fn random_hash() -> Hash {
    let mut buf = [0; 32];
    getrandom(&mut buf).unwrap();
    Hash::from_bytes(buf)
}

pub fn derive(context: &str, secret: &Hash) -> Hash {
    let mut hasher = Hasher::new_derive_key(context);
    hasher.update(secret.as_bytes());
    hasher.finalize()
}

/// Stores secret and next_secret.
///
/// # Examples
///
/// ```
/// use zebrachain::secretseed::{Seed, random_hash};
/// let initial_entropy = random_hash();
/// let new_entropy = random_hash();
/// let mut seed = Seed::create(&initial_entropy);
/// let next = seed.advance(&new_entropy);
/// assert_eq!(next.secret, seed.next_secret);
/// assert_ne!(seed, next);
/// seed.commit(next.clone());
/// assert_eq!(seed, next);
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct Seed {
    pub secret: Hash,
    pub next_secret: Hash,
}

impl Seed {
    pub fn new(secret: Hash, next_secret: Hash) -> Self {
        let seed = Self {
            secret,
            next_secret,
        };
        seed.check();
        seed
    }

    fn check(&self) {
        if self.secret == self.next_secret {
            panic!("secret and next_secret cannot be equal");
        }
    }

    /// Create a new seed by deriving [Seed::secret], [Seed::next_secret] from `initial_entropy`.
    pub fn create(initial_entropy: &Hash) -> Self {
        let secret = derive(SECRET_CONTEXT, initial_entropy);
        let next_secret = derive(NEXT_SECRET_CONTEXT, initial_entropy);
        Self::new(secret, next_secret)
    }

    /// Creates a new seed using entropy from [getrandom::getrandom()].
    pub fn auto_create() -> Self {
        let initial_entropy = random_hash();
        Self::create(&initial_entropy)
    }

    /// Create next seed by mixing `new_entropy` into the entropy chain.
    ///
    /// This is a critical part of the ZebraChain design.  If we simply created the next secret
    /// using `new_entropy`, that would be totally reasonable and is usually what happens when key
    /// rotation is done in most signing systems (er, if/when key rotation actually happens).
    ///
    /// But we can do better if we accumulate entropy in the secret chain, and then create the next
    /// secret by securely mixing the accumulated entropy with `new_entropy`. This is much more
    /// robust.
    ///
    /// See the source code for sure because it's simple, but important to understand.
    pub fn advance(&self, new_entropy: &Hash) -> Self {
        // We need to securely mix the previous entropy with new_entropy.  Hashing the concatenation
        // hash(next_secret || new_entropy) should be sufficient (right?), but
        // keyed_hash(next_secret, new_entropy) is definitely a more conservative construction with
        // little overhead, so we might as well do that (feedback encouraged).
        let next_next_secret = keyed_hash(self.next_secret.as_bytes(), new_entropy.as_bytes());
        Self::new(self.next_secret, next_next_secret)
    }

    /// Advance chain by mixing in new entropy from [getrandom::getrandom()].
    pub fn auto_advance(&self) -> Self {
        let new_entropy = random_hash();
        self.advance(&new_entropy)
    }

    /// Mutate seed state to match `next`.
    pub fn commit(&mut self, next: Seed) {
        if next.secret != self.next_secret {
            panic!("cannot commit out of sequence seed");
        }
        self.secret = next.secret;
        self.next_secret = next.next_secret;
        self.check();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake3::hash;
    use std::collections::HashSet;

    #[test]
    fn test_random_hash() {
        let count = 1024;
        let mut hset = HashSet::new();
        for _ in 0..count {
            assert!(hset.insert(random_hash()));
        }
        assert_eq!(hset.len(), count);
    }

    #[test]
    fn test_derive() {
        let secret = Hash::from_bytes([7; 32]);

        let h = derive("example0", &secret);
        assert_eq!(
            h.as_bytes(),
            &[
                201, 197, 207, 85, 251, 50, 175, 230, 93, 166, 135, 151, 254, 182, 137, 72, 247,
                158, 154, 71, 13, 107, 98, 185, 50, 220, 200, 223, 244, 224, 121, 36
            ]
        );

        let h = derive("example1", &secret);
        assert_eq!(
            h.as_bytes(),
            &[
                12, 255, 43, 240, 22, 55, 198, 18, 190, 243, 159, 226, 207, 193, 9, 243, 40, 12,
                148, 123, 160, 138, 63, 163, 136, 72, 203, 47, 243, 111, 81, 122
            ]
        );

        let secret = Hash::from_bytes([8; 32]);

        let h = derive("example0", &secret);
        assert_eq!(
            h.as_bytes(),
            &[
                85, 20, 18, 22, 96, 47, 74, 31, 16, 135, 2, 135, 147, 82, 64, 78, 92, 122, 8, 72,
                237, 33, 68, 119, 115, 195, 18, 171, 140, 184, 186, 101
            ]
        );

        let h = derive("example1", &secret);
        assert_eq!(
            h.as_bytes(),
            &[
                168, 183, 42, 224, 55, 249, 54, 53, 86, 216, 99, 36, 116, 156, 36, 118, 92, 240,
                132, 61, 243, 141, 196, 154, 196, 167, 54, 161, 134, 248, 4, 201
            ]
        );
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
        Seed::new(secret, next_secret);
    }

    #[test]
    fn test_seed_create() {
        let mut hset: HashSet<Hash> = HashSet::new();
        for i in 0..=255 {
            let entropy = Hash::from_bytes([i; 32]);
            let seed = Seed::create(&entropy);
            assert!(hset.insert(seed.secret));
            assert!(hset.insert(seed.next_secret));
        }
        assert_eq!(hset.len(), 512);
    }

    #[test]
    fn test_seed_advance() {
        let count = 10000;
        let entropy = Hash::from_bytes([69; 32]);
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
    fn test_seed_commit() {
        let entropy = Hash::from_bytes([69; 32]);
        let mut seed = Seed::create(&entropy);
        let next = seed.advance(&entropy);
        assert_ne!(seed, next);
        seed.commit(next.clone());
        assert_eq!(seed, next);
    }

    #[test]
    #[should_panic(expected = "cannot commit out of sequence seed")]
    fn test_seed_commit_panic1() {
        let entropy = Hash::from_bytes([69; 32]);
        let mut seed = Seed::create(&entropy);
        let a1 = seed.advance(&entropy);
        let a2 = a1.advance(&entropy);
        seed.commit(a2);
    }

    #[test]
    #[should_panic(expected = "secret and next_secret cannot be equal")]
    fn test_seed_commit_panic2() {
        let entropy = Hash::from_bytes([69; 32]);
        let mut seed = Seed::create(&entropy);
        let a1 = seed.advance(&entropy);
        let a2 = Seed {
            secret: a1.secret,
            next_secret: a1.secret,
        };
        seed.commit(a2);
    }
}
