use crate::always::*;
use blake2::{
    Blake2b, Blake2bMac, Digest,
    digest::{
        Mac,
        consts::{U24, U32, U40, U48},
    },
};
pub use getrandom::Error as EntropyError;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

type Blake2b320 = Blake2b<U40>;
type Blake2bMac192 = Blake2bMac<U24>;
type Blake2bMac256 = Blake2bMac<U32>;
type Blake2bMac384 = Blake2bMac<U48>;

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
        let mut hasher = Blake2b320::new();
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
            Blake2bMac384::new_with_salt_and_personal(self.as_bytes(), &[], &[]).unwrap();
        hasher.update(input);
        let output = hasher.finalize();
        Self::from_bytes(output.into_bytes().into())
    }

    /// Derive sub secret from this secret and the index as LE bytes.
    pub fn derive_with_index(&self, index: u128) -> Self {
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

    /// Derive a sub-secret from this secret and context bytes.
    pub fn derive_sub_secret_256(&self, context: &[u8; CONTEXT]) -> SubSecret256 {
        let mut hasher =
            Blake2bMac256::new_with_salt_and_personal(self.as_bytes(), &[], &[]).unwrap();
        hasher.update(context);
        let output = hasher.finalize();
        SubSecret::from_bytes(output.into_bytes().into())
    }

    /// Derive a sub-secret from this secret and context bytes.
    pub fn derive_sub_secret_192(&self, context: &[u8; CONTEXT]) -> SubSecret192 {
        let mut hasher =
            Blake2bMac192::new_with_salt_and_personal(self.as_bytes(), &[], &[]).unwrap();
        hasher.update(context);
        let output = hasher.finalize();
        SubSecret::from_bytes(output.into_bytes().into())
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

/// Simple buffer with ZeroizeOnDrop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SubSecret<const N: usize> {
    value: [u8; N],
}

impl<const N: usize> SubSecret<N> {
    /// Raw bytes of the sub-secret.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.value
    }

    /// Create a sub-secret from bytes.
    pub fn from_bytes(value: [u8; N]) -> Self {
        Self { value }
    }
}

/// A 192-bit derived secret.
///
/// This is used for the ChaCha20Poly1305 nonce.
pub type SubSecret192 = SubSecret<24>;

/// A 256-bit derived secret.
///
/// This is used for the ChaCha20Poly1305 key, the ed25519 seed, and the ML-DSA seed.
pub type SubSecret256 = SubSecret<32>;

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
    fn test_hash_display_fmt() {
        let hash = Hash::from_bytes([42; DIGEST]);
        assert_eq!(
            format!("{hash}"),
            "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
        );
    }

    #[test]
    fn test_hash_debug_fmt() {
        let hash = Hash::from_bytes([42; DIGEST]);
        assert_eq!(
            format!("{hash:?}"),
            "Hash(\"2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a\")"
        );
    }

    #[test]
    fn test_secret_debug_fmt() {
        let secret = Secret::generate().unwrap();
        assert_eq!(format!("{secret:?}"), "Secret(<hidden>)");
    }

    #[test]
    fn test_secret_derive_with_context() {
        let secret = Secret::from_bytes([7; SECRET]);

        let h = secret.derive_with_context(CONTEXT_SECRET);
        assert_eq!(
            h.as_bytes(),
            &[
                31, 218, 55, 236, 152, 73, 23, 132, 163, 223, 137, 171, 11, 247, 68, 114, 147, 46,
                52, 19, 222, 76, 171, 72, 104, 159, 151, 195, 190, 94, 105, 64, 76, 41, 173, 36,
                151, 18, 10, 75, 213, 154, 108, 115, 136, 13, 228, 30
            ]
        );

        let h = secret.derive_with_context(CONTEXT_SECRET_NEXT);
        assert_eq!(
            h.as_bytes(),
            &[
                79, 40, 4, 99, 143, 127, 37, 87, 239, 216, 177, 199, 15, 187, 131, 198, 250, 100,
                70, 93, 61, 54, 228, 185, 122, 37, 216, 73, 202, 75, 194, 46, 157, 34, 209, 43,
                186, 239, 178, 248, 17, 225, 117, 195, 239, 73, 58, 51
            ]
        );

        let secret = Secret::from_bytes([8; SECRET]);

        let h = secret.derive_with_context(CONTEXT_SECRET);
        assert_eq!(
            h.as_bytes(),
            &[
                206, 93, 22, 19, 230, 62, 212, 43, 142, 132, 106, 250, 131, 192, 10, 82, 252, 141,
                159, 53, 230, 70, 221, 86, 173, 255, 32, 192, 6, 136, 180, 201, 77, 7, 249, 202,
                39, 53, 40, 199, 132, 110, 185, 63, 99, 170, 64, 54
            ]
        );

        let h = secret.derive_with_context(CONTEXT_SECRET_NEXT);
        assert_eq!(
            h.as_bytes(),
            &[
                128, 252, 238, 121, 156, 196, 146, 254, 253, 251, 181, 195, 158, 52, 2, 164, 251,
                7, 116, 66, 186, 124, 220, 29, 170, 91, 36, 225, 127, 161, 188, 198, 152, 64, 105,
                198, 250, 95, 87, 143, 169, 14, 60, 119, 136, 181, 16, 70
            ]
        );
    }
}
