//! Entropy accumulating chain of secrets (in-memory).
//!
//! Note there is a lot of secret comparison in this module that relies on the constant time
//! comparison of [blake3::Hash] to be secure. Once the hash is configurable, we need to make sure
//! the [Secret] abstraction we use likewise ensures constant time comparison.

use crate::always::*;
use crate::errors::SecretBlockError;
use crate::hashing::{EntropyError, Secret, derive_secret, keyed_hash};
use core::ops::Range;

const SECRET_RANGE: Range<usize> = 0..SECRET;
const NEXT_SECRET_RANGE: Range<usize> = SECRET..SECRET * 2;

/// Stores secret and next_secret.
///
/// # Examples
///
/// ```
/// use zf_zebrachain::Seed;
/// let seed = Seed::auto_create().unwrap();
/// let next = seed.auto_advance().unwrap();
/// assert_eq!(next.secret, seed.next_secret);
/// assert_ne!(seed, next);
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Seed {
    /// Root secret used to sign current block.
    pub secret: Secret,

    /// Root secret used for signing the next block.
    pub next_secret: Secret,
}

impl Seed {
    pub(crate) fn new(secret: Secret, next_secret: Secret) -> Self {
        if secret == next_secret {
            panic!("new(): secret and next_secret cannot be equal");
        }
        Self {
            secret,
            next_secret,
        }
    }

    /// Create a new seed by deriving [Seed::secret], [Seed::next_secret] from `initial_entropy`.
    pub fn create(initial_entropy: &Secret) -> Self {
        let secret = derive_secret(CONTEXT_SECRET, initial_entropy);
        let next_secret = derive_secret(CONTEXT_SECRET_NEXT, initial_entropy);
        Self::new(secret, next_secret)
    }

    /// Creates a new seed using the initial entropy from [getrandom::fill()].
    pub fn auto_create() -> Result<Self, EntropyError> {
        let initial_entropy = Secret::generate()?; // Only this part can fail
        Ok(Self::create(&initial_entropy))
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
    pub fn advance(&self, new_entropy: &Secret) -> Self {
        let next_next_secret = keyed_hash(self.next_secret.as_bytes(), new_entropy.as_bytes());
        Self::new(self.next_secret, next_next_secret)
    }

    /// Advance chain by mixing in new entropy from [getrandom::fill()].
    pub fn auto_advance(&self) -> Result<Self, EntropyError> {
        let new_entropy = Secret::generate()?; // Only this part can fail
        Ok(self.advance(&new_entropy))
    }

    /// Load a seed from a buffer.
    pub fn from_buf(buf: &[u8]) -> Result<Self, SecretBlockError> {
        assert_eq!(buf.len(), SEED);
        let secret = get_secret(buf, SECRET_RANGE);
        let next_secret = get_secret(buf, NEXT_SECRET_RANGE);
        if secret.is_zeros() || next_secret.is_zeros() || secret == next_secret {
            Err(SecretBlockError::Seed)
        } else {
            Ok(Self {
                secret,
                next_secret,
            })
        }
    }

    /// Write seed to buffer.
    pub fn write_to_buf(&self, buf: &mut [u8]) {
        assert_eq!(buf.len(), SEED);
        set_secret(buf, SECRET_RANGE, &self.secret);
        set_secret(buf, NEXT_SECRET_RANGE, &self.next_secret);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::hash;
    use std::collections::HashSet;

    #[test]
    fn test_seed_new() {
        let secret = Secret::from_bytes(*hash(&[42; 32]).as_bytes());
        let next_secret = Secret::from_bytes(*hash(&[69; 32]).as_bytes());
        let seed = Seed::new(secret, next_secret);
        assert_eq!(seed.secret, secret);
        assert_eq!(seed.next_secret, next_secret);
    }

    #[test]
    #[should_panic(expected = "new(): secret and next_secret cannot be equal")]
    fn test_seed_new_panic() {
        let secret = Secret::from_bytes(*hash(&[42; 32]).as_bytes());
        let next_secret = Secret::from_bytes(*hash(&[42; 32]).as_bytes());
        Seed::new(secret, next_secret);
    }

    #[test]
    fn test_seed_from_buf() {
        let zero = Secret::from_bytes([0; SECRET]);
        let a = Secret::from_bytes([41; SECRET]);
        let b = Secret::from_bytes([42; SECRET]);

        // (zero, zero)
        let mut buf = [0; SEED];
        assert_eq!(Seed::from_buf(&buf), Err(SecretBlockError::Seed));

        // (a, zero)
        buf[SECRET_RANGE].copy_from_slice(a.as_bytes());
        assert_eq!(Seed::from_buf(&buf), Err(SecretBlockError::Seed));

        // (a, a)
        buf[NEXT_SECRET_RANGE].copy_from_slice(a.as_bytes());
        assert_eq!(Seed::from_buf(&buf), Err(SecretBlockError::Seed));

        // (a, b)
        buf[NEXT_SECRET_RANGE].copy_from_slice(b.as_bytes());
        assert_eq!(Seed::from_buf(&buf), Ok(Seed::new(a, b)));

        // (zero, b)
        buf[SECRET_RANGE].copy_from_slice(zero.as_bytes());
        assert_eq!(Seed::from_buf(&buf), Err(SecretBlockError::Seed));
    }

    #[test]
    fn test_seed_roundtrip() {
        for _ in 0..420 {
            let secret = Secret::generate().unwrap();
            let next_secret = Secret::generate().unwrap();
            let seed = Seed::new(secret, next_secret);
            let mut buf = [0; SEED];
            seed.write_to_buf(&mut buf);
            let seed2 = Seed::from_buf(&buf).unwrap();
            assert_eq!(seed2.secret, secret);
            assert_eq!(seed2.next_secret, next_secret);
            assert_eq!(seed2, seed);
        }
    }

    #[test]
    fn test_seed_roundtrip_buffer() {
        for _ in 0..420 {
            let mut buf = [0; SEED];
            getrandom::fill(&mut buf).unwrap();
            let buf = buf;
            let seed = Seed::from_buf(&buf).unwrap();
            assert_eq!(seed.secret, Secret::from_slice(&buf[SECRET_RANGE]).unwrap());
            assert_eq!(
                seed.next_secret,
                Secret::from_slice(&buf[NEXT_SECRET_RANGE]).unwrap()
            );
            let mut buf2 = [0; SEED];
            seed.write_to_buf(&mut buf2);
            assert_eq!(buf2, buf);
        }
    }

    #[test]
    fn test_seed_create() {
        let mut hset: HashSet<Secret> = HashSet::new();
        for i in 0..=255 {
            let entropy = Secret::from_bytes([i; 32]);
            let seed = Seed::create(&entropy);
            assert!(hset.insert(seed.secret));
            assert!(hset.insert(seed.next_secret));
        }
        assert_eq!(hset.len(), 512);
    }

    #[test]
    fn test_seed_advance() {
        let count = 10000;
        let entropy = Secret::from_bytes([69; 32]);
        let mut seed = Seed::create(&entropy);
        let mut hset: HashSet<Secret> = HashSet::new();
        assert!(hset.insert(seed.secret));
        assert!(hset.insert(seed.next_secret));
        for _ in 0..count {
            seed = seed.advance(&entropy);
            assert!(!hset.insert(seed.secret)); // Should already be contained
            assert!(hset.insert(seed.next_secret));
        }
        assert_eq!(hset.len(), count + 2);
    }
}
