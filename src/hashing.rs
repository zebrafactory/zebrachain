use crate::always::*;
use blake2::{
    Blake2b, Blake2bMac, Digest,
    digest::{Mac, consts::U32},
};
pub use getrandom::Error as EntropyError;
use subtle::{Choice, ConstantTimeEq};

type Blake2b256 = Blake2b<U32>;
type Blake2bMac256 = Blake2bMac<U32>;
//type Blake2b384 = Blake2b<U48>;

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

    /// Experimental keyed hashing with blake2b
    pub fn keyed_hash2(&self, input: &[u8]) -> Self {
        if input.len() < 8 {
            panic!(
                "Secret.keyed_hash(): input must be at least 8 bytes, got {}",
                input.len()
            );
        }
        let mut hasher =
            Blake2bMac256::new_with_salt_and_personal(self.as_bytes(), &[], &[]).unwrap();
        hasher.update(input);
        let output = hasher.finalize();
        Self::from_bytes(output.into_bytes().into())
    }

    /// Keyed hash
    pub fn keyed_hash(&self, input: &[u8]) -> Self {
        let output = blake3::keyed_hash(self.as_bytes(), input);
        Self::from_bytes(*output.as_bytes())
    }

    /// Derive sub secret from this secret and the index as LE bytes.
    pub fn derive_with_index(&self, index: u64) -> Self {
        self.keyed_hash(&index.to_le_bytes())
    }

    /// Derive sub secret from this secret and context bytes.
    pub fn derive_with_context(&self, context: &[u8; CONTEXT]) -> Self {
        self.keyed_hash(context)
    }

    /// Mix new entropy with this secret to create next secret.
    pub fn next(&self, new_entropy: &Self) -> Self {
        self.keyed_hash(new_entropy.as_bytes())
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
    fn test_secret_derive_with_context() {
        let secret = Secret::from_bytes([7; 32]);

        let h = secret.derive_with_context(CONTEXT_SECRET);
        assert_eq!(
            h.as_bytes(),
            &[
                237, 41, 26, 111, 128, 91, 108, 191, 144, 205, 125, 20, 166, 179, 4, 173, 195, 127,
                157, 202, 199, 208, 108, 187, 106, 113, 15, 193, 130, 12, 164, 143
            ]
        );

        let h = secret.derive_with_context(CONTEXT_SECRET_NEXT);
        assert_eq!(
            h.as_bytes(),
            &[
                179, 29, 95, 3, 85, 14, 2, 129, 144, 5, 84, 13, 186, 229, 168, 243, 59, 56, 253,
                82, 167, 125, 188, 37, 255, 183, 2, 25, 110, 47, 201, 79
            ]
        );

        let secret = Secret::from_bytes([8; 32]);

        let h = secret.derive_with_context(CONTEXT_SECRET);
        assert_eq!(
            h.as_bytes(),
            &[
                112, 184, 146, 57, 65, 142, 223, 113, 195, 133, 163, 255, 27, 13, 69, 123, 180,
                190, 137, 233, 197, 255, 126, 10, 23, 59, 100, 16, 92, 255, 10, 233
            ]
        );

        let h = secret.derive_with_context(CONTEXT_SECRET_NEXT);
        assert_eq!(
            h.as_bytes(),
            &[
                78, 133, 40, 203, 84, 81, 182, 43, 183, 236, 154, 199, 160, 138, 139, 63, 192, 122,
                100, 39, 84, 20, 43, 115, 157, 51, 105, 131, 119, 113, 46, 119
            ]
        );
    }
}
