//! Entropy accumulating chain of secrets (in-memory).
//!
//! Note there is a lot of secret comparison in this module that relies on the constant time
//! comparison of [blake3::Hash] to be secure. Once the hash is configurable, we need to make sure
//! the [Secret] abstraction we use likewise ensures constant time comparison.

use crate::always::*;
use crate::errors::SecretBlockError;
use blake3::{Hash, Hasher, keyed_hash};
pub use getrandom::Error;
use std::ops::Range;

const SECRET_RANGE: Range<usize> = 0..DIGEST;
const NEXT_SECRET_RANGE: Range<usize> = DIGEST..DIGEST * 2;

/// A secret buffer with constant time comparison and zeroize.
///
/// This currently is just an alias for [blake3::Hash] because it gives us the features we need.
/// Eventually we should use separate types and abstractions for the notion of a Secret buffer vs
/// a Hash buffer as they will almost certainly need to differ in some configurations.
pub type Secret = Hash;

/// Return a [Secret] buffer with entropy from [getrandom::fill()].
pub fn generate_secret() -> Result<Secret, Error> {
    let mut buf = [0; 32];
    match getrandom::fill(&mut buf) {
        Ok(_) => Ok(Secret::from_bytes(buf)),
        Err(err) => Err(err),
    }
}

/// Derive a domain specific [Secret] from a context string and a root secret.
///
/// When doing hybrid signing, it is critical to derive a unique secret for each algorithm (say,
/// one for ed25519 and another for ML-DSA).
///
/// And even if signing with a single algorithm, we still should use a derived secret instead of the
/// root secret directly.
pub fn derive_secret(context: &str, secret: &Secret) -> Secret {
    if context.len() != 64 {
        panic!(
            "derive_secret(): context string length must be 64; got {}",
            context.len()
        );
    }
    let mut hasher = Hasher::new_derive_key(context);
    hasher.update(secret.as_bytes());
    hasher.finalize()
}

/// Stores secret and next_secret.
///
/// # Examples
///
/// ```
/// use zf_zebrachain::{Seed, generate_secret};
/// let initial_entropy = generate_secret().unwrap();
/// let mut seed = Seed::create(&initial_entropy);
/// let new_entropy = generate_secret().unwrap();
/// let next = seed.advance(&new_entropy);
/// assert_eq!(next.secret, seed.next_secret);
/// assert_ne!(seed, next);
/// seed.commit(next.clone());
/// assert_eq!(seed, next);
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Seed {
    pub secret: Secret,
    pub next_secret: Secret,
}

impl Seed {
    pub fn new(secret: Secret, next_secret: Secret) -> Self {
        if secret == next_secret {
            panic!("new(): secret and next_secret cannot be equal");
        }
        Self {
            secret,
            next_secret,
        }
    }

    pub fn from_buf(buf: &[u8]) -> Result<Self, SecretBlockError> {
        assert_eq!(buf.len(), SEED);
        let secret = get_hash(buf, SECRET_RANGE);
        let next_secret = get_hash(buf, NEXT_SECRET_RANGE);
        let zero_hash = Hash::from_bytes([0; DIGEST]);
        if secret == zero_hash || next_secret == zero_hash || secret == next_secret {
            Err(SecretBlockError::Seed)
        } else {
            Ok(Self {
                secret,
                next_secret,
            })
        }
    }

    pub fn write_to_buf(&self, buf: &mut [u8]) {
        assert_eq!(buf.len(), SEED);
        set_hash(buf, SECRET_RANGE, &self.secret);
        set_hash(buf, NEXT_SECRET_RANGE, &self.next_secret);
    }

    /// Create a new seed by deriving [Seed::secret], [Seed::next_secret] from `initial_entropy`.
    pub fn create(initial_entropy: &Secret) -> Self {
        let secret = derive_secret(CONTEXT_SECRET, initial_entropy);
        let next_secret = derive_secret(CONTEXT_SECRET_NEXT, initial_entropy);
        Self::new(secret, next_secret)
    }

    /// Creates a new seed using entropy from [generate_secret()].
    pub fn auto_create() -> Result<Self, Error> {
        let initial_entropy = generate_secret()?; // Only this part can fail
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

    /// Advance chain by mixing in new entropy from [generate_secret()].
    pub fn auto_advance(&self) -> Result<Self, Error> {
        let new_entropy = generate_secret()?; // Only this part can fail
        Ok(self.advance(&new_entropy))
    }

    /// Mutate seed state to match `next`.
    pub fn commit(&mut self, next: Seed) {
        if next.secret == next.next_secret {
            panic!("commit(): secret and next_secret cannot be equal");
        }
        if next.secret != self.next_secret {
            panic!("commit(): cannot commit out of sequence seed");
        }
        self.secret = next.secret;
        self.next_secret = next.next_secret;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake3::hash;
    use std::collections::HashSet;

    #[test]
    fn test_generate_secret() {
        let count = 1024;
        let mut hset = HashSet::new();
        for _ in 0..count {
            assert!(hset.insert(generate_secret().unwrap()));
        }
        assert_eq!(hset.len(), count);
    }

    #[test]
    fn test_derive_secret() {
        let secret = Hash::from_bytes([7; 32]);

        let h = derive_secret(CONTEXT_SECRET, &secret);
        assert_eq!(
            h.as_bytes(),
            &[
                120, 255, 86, 223, 30, 100, 162, 199, 106, 136, 172, 87, 236, 29, 37, 87, 54, 34,
                187, 11, 86, 136, 243, 38, 218, 235, 136, 210, 10, 49, 145, 205
            ]
        );

        let h = derive_secret(CONTEXT_SECRET_NEXT, &secret);
        assert_eq!(
            h.as_bytes(),
            &[
                56, 77, 119, 202, 143, 168, 34, 136, 205, 197, 90, 11, 162, 112, 64, 45, 180, 80,
                53, 21, 110, 79, 164, 134, 252, 40, 223, 195, 105, 145, 116, 30
            ]
        );

        let secret = Hash::from_bytes([8; 32]);

        let h = derive_secret(CONTEXT_SECRET, &secret);
        assert_eq!(
            h.as_bytes(),
            &[
                204, 111, 146, 79, 175, 44, 54, 156, 189, 251, 132, 13, 239, 136, 191, 186, 33,
                207, 252, 183, 28, 52, 122, 92, 77, 16, 181, 179, 130, 180, 83, 141
            ]
        );

        let h = derive_secret(CONTEXT_SECRET_NEXT, &secret);
        assert_eq!(
            h.as_bytes(),
            &[
                21, 128, 0, 241, 82, 225, 6, 165, 5, 12, 101, 182, 221, 147, 193, 220, 120, 250,
                138, 223, 152, 199, 78, 68, 69, 51, 238, 203, 135, 83, 186, 246
            ]
        );
    }

    #[test]
    #[should_panic(expected = "derive_secret(): context string length must be 64; got 63")]
    fn test_derive_secret_panic_low() {
        let secret = generate_secret().unwrap();
        derive_secret(&CONTEXT_SECRET[0..63], &secret);
    }

    #[test]
    #[should_panic(expected = "derive_secret(): context string length must be 64; got 65")]
    fn test_derive_secret_panic_high() {
        let secret = generate_secret().unwrap();
        let mut context = String::from(CONTEXT_SECRET);
        context.push('7');
        derive_secret(&context, &secret);
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
    #[should_panic(expected = "new(): secret and next_secret cannot be equal")]
    fn test_seed_new_panic() {
        let secret = hash(&[42; 32]);
        let next_secret = hash(&[42; 32]);
        Seed::new(secret, next_secret);
    }

    #[test]
    fn test_seed_from_buf() {
        let zero = Hash::from_bytes([0; DIGEST]);
        let a = Hash::from_bytes([41; DIGEST]);
        let b = Hash::from_bytes([42; DIGEST]);

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
            let secret = generate_secret().unwrap();
            let next_secret = generate_secret().unwrap();
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
            assert_eq!(seed.secret, Hash::from_slice(&buf[SECRET_RANGE]).unwrap());
            assert_eq!(
                seed.next_secret,
                Hash::from_slice(&buf[NEXT_SECRET_RANGE]).unwrap()
            );
            let mut buf2 = [0; SEED];
            seed.write_to_buf(&mut buf2);
            assert_eq!(buf2, buf);
        }
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
    #[should_panic(expected = "commit(): cannot commit out of sequence seed")]
    fn test_seed_commit_panic1() {
        let entropy = Hash::from_bytes([69; 32]);
        let mut seed = Seed::create(&entropy);
        let a1 = seed.advance(&entropy);
        let a2 = a1.advance(&entropy);
        seed.commit(a2);
    }

    #[test]
    #[should_panic(expected = "commit(): secret and next_secret cannot be equal")]
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
