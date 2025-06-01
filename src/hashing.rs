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

#[derive(Debug)]
pub enum HexError {
    Len(usize),
    Byte(u8),
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

    /// Decode a `Hash` from lowercase hexadecimal.
    pub fn from_hex(hex: impl AsRef<[u8]>) -> Result<Self, HexError> {
        // Totally copied from blake3::Hash::from_hex()
        fn hex_val(byte: u8) -> Result<u8, HexError> {
            match byte {
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                b'0'..=b'9' => Ok(byte - b'0'),
                _ => Err(HexError::Byte(byte)),
            }
        }
        let hex_bytes: &[u8] = hex.as_ref();
        if hex_bytes.len() != DIGEST * 2 {
            return Err(HexError::Len(hex_bytes.len()));
        }
        let mut hash_bytes: [u8; DIGEST] = [0; DIGEST];
        for i in 0..DIGEST {
            hash_bytes[i] = 16 * hex_val(hex_bytes[2 * i])? + hex_val(hex_bytes[2 * i + 1])?;
        }
        Ok(Self::from_bytes(hash_bytes))
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
#[derive(Eq, Clone, Copy)]
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
    pub fn keyed_hash(&self, input: &[u8]) -> Self {
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

    /// Derive sub secret from this secret and the index as LE bytes.
    pub fn derive_with_index(&self, index: u64) -> Self {
        self.keyed_hash(&index.to_le_bytes())
    }

    /// Derive sub secret from this secret and context bytes.
    pub fn derive_with_context(&self, context: &[u8; CONTEXT]) -> Self {
        self.keyed_hash(context)
    }

    /// Derive sub secret from this secret and the bytes in [Hash][crate::Hash].
    pub fn derive_with_hash(&self, hash: &Hash) -> Self {
        self.keyed_hash(hash.as_bytes())
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

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("Secret(<hidden>)")
    }
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
    fn test_secret_debug_fmt() {
        let secret = Secret::generate().unwrap();
        assert_eq!(format!("{secret:?}"), "Secret(<hidden>)");
    }

    #[test]
    fn test_secret_derive_with_context() {
        let secret = Secret::from_bytes([7; 32]);

        let h = secret.derive_with_context(CONTEXT_SECRET);
        assert_eq!(
            h.as_bytes(),
            &[
                87, 118, 72, 245, 138, 235, 86, 65, 70, 188, 121, 27, 69, 221, 71, 164, 93, 60,
                237, 78, 91, 183, 42, 65, 133, 34, 231, 95, 253, 254, 92, 193
            ]
        );

        let h = secret.derive_with_context(CONTEXT_SECRET_NEXT);
        assert_eq!(
            h.as_bytes(),
            &[
                15, 132, 133, 121, 216, 222, 179, 231, 88, 144, 203, 87, 71, 95, 207, 87, 88, 31,
                196, 206, 29, 1, 81, 249, 186, 186, 79, 131, 33, 110, 82, 53
            ]
        );

        let secret = Secret::from_bytes([8; 32]);

        let h = secret.derive_with_context(CONTEXT_SECRET);
        assert_eq!(
            h.as_bytes(),
            &[
                191, 56, 136, 57, 167, 49, 108, 32, 88, 232, 2, 191, 11, 8, 40, 238, 198, 165, 176,
                60, 207, 123, 113, 222, 146, 178, 134, 52, 25, 167, 70, 211
            ]
        );

        let h = secret.derive_with_context(CONTEXT_SECRET_NEXT);
        assert_eq!(
            h.as_bytes(),
            &[
                196, 240, 189, 158, 19, 38, 152, 150, 62, 171, 11, 80, 1, 3, 154, 167, 74, 180, 54,
                228, 159, 237, 32, 63, 71, 82, 95, 247, 74, 87, 11, 195
            ]
        );
    }
}
