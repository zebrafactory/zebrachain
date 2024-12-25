//! Entropy accumulating chain of secrets (in-memory).

use blake3::{keyed_hash, Hash, Hasher};
use std::fs::File;
use std::io::Error as IoError;
use std::io::Result as IoResult;
use std::io::{Read, Seek, SeekFrom, Write};

static SECRET_CONTEXT: &str = "foo";
static NEXT_SECRET_CONTEXT: &str = "bar";

pub fn derive(context: &str, secret: &[u8]) -> Hash {
    let mut hasher = Hasher::new_derive_key(context);
    hasher.update(secret);
    hasher.finalize()
}

/// Stores secret and next_secret.
///
/// # Examples
///
/// ```
/// use zebrachain::secretseed::Seed;
/// let initial_entropy = [42u8; 32];
/// let new_entropy = [69u8; 32];
/// let seed = Seed::create(&initial_entropy);
/// let next = seed.advance(&new_entropy);
/// assert_eq!(next.secret, seed.next_secret);
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

    pub fn create(initial_entropy: &[u8; 32]) -> Self {
        let secret = derive(SECRET_CONTEXT, initial_entropy);
        let next_secret = derive(NEXT_SECRET_CONTEXT, initial_entropy);
        Self::new(secret, next_secret)
    }

    /// Create next seed by mixing `new_entropy` into the entropy chain.
    ///
    /// This is a critical part of the ZebraChain design.  If we simply created the next secret
    /// using `new_entropy`, that would be totally reasonable and is usually what happens when key
    /// rotation is done in existing signing systems (er, if/when key rotation actually happens).
    ///
    /// But we can do better if we accumulate entropy in the secret chain, and then create the next
    /// secret by securely mixing the accumulated entropy with `new_entropy`. This is much more
    /// robust.
    ///
    /// See the source code for sure because it's simple, but important to understand.
    pub fn advance(&self, new_entropy: &[u8; 32]) -> Self {
        // We need to securely mix the previous entropy with new_entropy.  Hashing the concatenation
        // hash(next_secret || new_entropy) should be sufficient (right?), but
        // keyed_hash(next_secret, new_entropy) is definitely a more conservative construction with
        // little overhead, so we might as well do that (feedback encouraged).
        //
        // Mr. Zebra's rationale as to whether the key passed to keyed_hash() should be
        // `self.next_secret` or `new_entropy` goes like this: we should use the least attacker
        // knowable, which in this case will usually be `self.next_secret` (because of the entropy
        // accumulation).
        let next_next_secret = keyed_hash(self.next_secret.as_bytes(), new_entropy);
        Self::new(self.next_secret, next_next_secret)
    }

    pub fn commit(&mut self, seed: Seed) {
        if seed.secret != self.next_secret {
            panic!("cannot commit out of sequence seed");
        }
        if seed.secret == seed.next_secret {
            panic!("secret and next_secret cannot be equal");
        }
        self.secret = seed.secret;
        self.next_secret = seed.next_secret;
    }

    pub fn load(buf: &[u8; 64]) -> IoResult<Self> {
        let secret = Hash::from_bytes(buf[0..32].try_into().unwrap());
        let next_secret = Hash::from_bytes(buf[32..64].try_into().unwrap());
        if secret == next_secret {
            Err(IoError::other("secret and next_secret match"))
        } else {
            Ok(Self::new(secret, next_secret))
        }
    }
}

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
        self.seed.commit(seed);
        self.file.write_all(self.seed.next_secret.as_bytes())?;
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
    fn derive_key() {
        let secret = [7; 32];

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

        let secret = [8; 32];

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
        let seed = Seed::new(secret, next_secret);
    }

    #[test]
    fn test_seed_load() {
        let mut buf: [u8; 64] = [0; 64];
        buf[0..32].copy_from_slice(&[42; 32]);
        buf[32..64].copy_from_slice(&[69; 32]);
        let seed = Seed::load(&buf).unwrap();
        assert_eq!(seed.secret.as_bytes(), &[42; 32]);
        assert_eq!(seed.next_secret.as_bytes(), &[69; 32]);

        let buf = [69; 64];
        assert!(Seed::load(&buf).is_err());
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
    fn test_seed_commit() {
        let entropy = [69; 32];
        let mut seed = Seed::create(&entropy);
        let next = seed.advance(&entropy);
        assert_ne!(seed, next);
        seed.commit(next.clone());
        assert_eq!(seed, next);
    }

    #[test]
    #[should_panic(expected = "cannot commit out of sequence seed")]
    fn test_seed_commit_panic1() {
        let entropy = [69; 32];
        let mut seed = Seed::create(&entropy);
        let a1 = seed.advance(&entropy);
        let a2 = a1.advance(&entropy);
        seed.commit(a2);
    }

    #[test]
    #[should_panic(expected = "secret and next_secret cannot be equal")]
    fn test_seed_commit_panic2() {
        let entropy = [69; 32];
        let mut seed = Seed::create(&entropy);
        let a1 = seed.advance(&entropy);
        let a2 = Seed {
            secret: a1.secret,
            next_secret: a1.secret,
        };
        seed.commit(a2);
    }

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
