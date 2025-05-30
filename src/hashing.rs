use crate::always::*;
use blake2::{Blake2b, Digest, digest::consts::U32};
pub use getrandom::Error as EntropyError;
use subtle::{Choice, ConstantTimeEq};

type Blake2b256 = Blake2b<U32>;
//type Blake2b384 = Blake2b<U48>;

/*
/// A generic array with better ergonomics.
pub struct GenericHash<const N: usize> {
    value: [u8; N],
}

impl<const N: usize> GenericHash<N> {
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.value
    }

    pub fn from_bytes(value: [u8; N]) -> Self {
        Self { value }
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::new();
        let table = b"0123456789abcdef";
        for &b in self.value.iter() {
            s.push(table[(b >> 4) as usize] as char);
            s.push(table[(b & 0xf) as usize] as char);
        }
        s
    }
}

pub type Hash256 = GenericHash<32>;
pub type Hash384 = GenericHash<48>;

pub fn hash256(input: &[u8]) -> Hash256 {
    let mut value = [0; 32];
    let mut hasher = Blake2b256::new();
    hasher.update(input);
    hasher.finalize_into((&mut value).into());
    Hash256::from_bytes(value)
}

pub fn hash384(input: &[u8]) -> Hash384 {
    let mut value = [0; 48];
    let mut hasher = Blake2b384::new();
    hasher.update(input);
    hasher.finalize_into((&mut value).into());
    Hash384::from_bytes(value)
}
*/

/// Buffer containing the hash digest, with constant time comparison.
#[derive(Eq, Clone, Copy)]
pub struct Hash {
    value: [u8; DIGEST],
}

impl Hash {
    /// The raw bytes of the `Hash`.
    pub fn as_bytes(&self) -> &[u8; DIGEST] {
        &self.value
    }

    /// Create from bytes.
    pub fn from_bytes(value: [u8; DIGEST]) -> Self {
        Self { value }
    }

    /// Load from a slice
    pub fn from_slice(bytes: &[u8]) -> Result<Self, core::array::TryFromSliceError> {
        Ok(Self::from_bytes(bytes.try_into()?))
    }

    /// Constant time check of whether every byte is a zero.
    pub fn is_zeros(&self) -> bool {
        // FIXME: Do this without comparing to another [u8; SECRET]
        self.value.ct_eq(&[0; DIGEST]).into()
    }

    /// Decode from hex
    pub fn from_hex(hex: impl AsRef<[u8]>) -> Result<Self, blake3::HexError> {
        let inner = blake3::Hash::from_hex(hex)?; // OMS, FIXME
        Ok(Self {
            value: *inner.as_bytes(),
        })
    }

    /// Encode in lowercase hexidecimal
    pub fn to_hex(&self) -> arrayvec::ArrayString<{ DIGEST * 2 }> {
        // Totally copied from blake3::Hash.to_hex()
        let mut hex = arrayvec::ArrayString::new();
        let table = b"0123456789abcdef";
        for &b in self.value.iter() {
            hex.push(table[(b >> 4) as usize] as char);
            hex.push(table[(b & 0xf) as usize] as char);
        }
        hex
    }

    /// Compute hash of `input`, returning `Hash`.
    pub fn compute(input: &[u8]) -> Self {
        let mut hasher = Blake2b256::new();
        hasher.update(input);
        let output = hasher.finalize();
        Self::from_bytes(output.into())
    }
}

impl ConstantTimeEq for Hash {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.value.ct_eq(&other.value)
    }
}

impl PartialEq for Hash {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl core::hash::Hash for Hash {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state)
    }
}

impl core::fmt::Debug for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let hex = self.to_hex();
        let hex: &str = hex.as_str();
        f.debug_tuple("Hash").field(&hex).finish()
    }
}

impl core::fmt::Display for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(self.to_hex().as_str())
    }
}

/// Stores a secret in a buffer with constant time comparison.
///
/// OH MY SCIENCE, FIXME: This needs to zeroize on drop
#[derive(Debug, Eq, Clone, Copy)]
pub struct Secret {
    value: [u8; SECRET],
}

impl Secret {
    /// The raw bytes of the `Secret`.
    pub fn as_bytes(&self) -> &[u8; SECRET] {
        &self.value
    }

    /// Create from bytes.
    pub fn from_bytes(value: [u8; SECRET]) -> Self {
        Self { value }
    }

    /// Load from a slice
    pub fn from_slice(bytes: &[u8]) -> Result<Self, core::array::TryFromSliceError> {
        Ok(Self::from_bytes(bytes.try_into()?))
    }

    /// Constant time check of whether every byte is a zero.
    pub fn is_zeros(&self) -> bool {
        // FIXME: Do this without comparing to another [u8; SECRET]
        self.value.ct_eq(&[0; SECRET]).into()
    }

    /// Return a [Secret] with entropy from [getrandom::fill()].
    pub fn generate() -> Result<Self, EntropyError> {
        let mut buf = [0; SECRET];
        match getrandom::fill(&mut buf) {
            Ok(_) => Ok(Self::from_bytes(buf)),
            Err(err) => Err(err),
        }
    }

    /// Mix new entropy with this secret to create next secret.
    pub fn next(&self, new_entropy: &Self) -> Self {
        let next = blake3::keyed_hash(self.as_bytes(), new_entropy.as_bytes());
        Secret::from_bytes(*next.as_bytes())
    }
}

impl ConstantTimeEq for Secret {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.value.ct_eq(&other.value)
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl core::hash::Hash for Secret {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state)
    }
}

/// Keyed hash, yo
pub fn keyed_hash(key: &[u8; 32], input: &[u8]) -> Secret {
    Secret::from_bytes(*blake3::keyed_hash(key, input).as_bytes())
}

/// Derive a domain specific [Secret] from a context string and a root secret.
///
/// When doing hybrid signing, it is critical to derive a unique secret for each algorithm (say,
/// one for ed25519 and another for ML-DSA).
///
/// And even if signing with a single algorithm, we still should use a derived secret instead of the
/// root secret directly.
pub(crate) fn derive_secret(context: &str, secret: &Secret) -> Secret {
    if context.len() != 64 {
        panic!(
            "derive_secret(): context string length must be 64; got {}",
            context.len()
        );
    }
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(secret.as_bytes());
    Secret::from_bytes(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /*
    #[test]
    fn test_blake2b() {
        let msg = b"yo dawg, wut up";
        let _h = hash384(msg);
        let _h = hash256(msg);
    }
    */

    #[test]
    fn test_generate_secret() {
        let count = 1024;
        let mut hset = HashSet::new();
        for _ in 0..count {
            assert!(hset.insert(Secret::generate().unwrap()));
        }
        assert_eq!(hset.len(), count);
    }

    #[test]
    fn test_derive_secret() {
        let secret = Secret::from_bytes([7; 32]);

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

        let secret = Secret::from_bytes([8; 32]);

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
        let secret = Secret::generate().unwrap();
        derive_secret(&CONTEXT_SECRET[0..63], &secret);
    }

    #[test]
    #[should_panic(expected = "derive_secret(): context string length must be 64; got 65")]
    fn test_derive_secret_panic_high() {
        let secret = Secret::generate().unwrap();
        let mut context = String::from(CONTEXT_SECRET);
        context.push('7');
        derive_secret(&context, &secret);
    }
}
