use crate::EntropyError;
use crate::always::*;
use blake2::{
    Blake2b, Blake2bMac, Digest,
    digest::{
        Mac,
        consts::{U24, U32, U45, U48},
    },
};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

type Blake2b360 = Blake2b<U45>;
type Blake2bMac192 = Blake2bMac<U24>;
type Blake2bMac256 = Blake2bMac<U32>;
type Blake2bMac384 = Blake2bMac<U48>;

/// Error when trying to decode a Zbase32 encoded [Hash](crate::Hash).
#[derive(Debug, PartialEq, Eq)]
pub enum Zbase32Error {
    /// The length is wrong
    BadLen(usize),

    /// Contains an invalid byte
    BadByte(u8),
}

// Encode in Zbase32.
fn zbase32_enc_into(src: &[u8], dst: &mut [u8]) {
    assert_eq!(dst.len(), src.len() * 8 / 5);
    let table = b"456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for i in 0..src.len() / 5 {
        // Pack 40 bits into taxi (8 bits at a time)
        let a = i * 5;
        let taxi = src[a] as u64;
        let taxi = src[a + 1] as u64 | taxi << 8;
        let taxi = src[a + 2] as u64 | taxi << 8;
        let taxi = src[a + 3] as u64 | taxi << 8;
        let taxi = src[a + 4] as u64 | taxi << 8;

        // Unpack 40 bits from taxi (5 bits at a time)
        let b = i * 8;
        dst[b] = table[((taxi >> 35) & 31) as usize];
        dst[b + 1] = table[((taxi >> 30) & 31) as usize];
        dst[b + 2] = table[((taxi >> 25) & 31) as usize];
        dst[b + 3] = table[((taxi >> 20) & 31) as usize];
        dst[b + 4] = table[((taxi >> 15) & 31) as usize];
        dst[b + 5] = table[((taxi >> 10) & 31) as usize];
        dst[b + 6] = table[((taxi >> 5) & 31) as usize];
        dst[b + 7] = table[(taxi & 31) as usize];
    }
}

fn zbase32_dec_into(src: &[u8], dst: &mut [u8]) -> Result<(), Zbase32Error> {
    assert_eq!(dst.len(), DIGEST);
    if src.len() != Z32DIGEST {
        return Err(Zbase32Error::BadLen(src.len()));
    }

    fn zb32_to_u64(byte: u8) -> Result<u64, Zbase32Error> {
        match byte {
            b'4'..=b'9' => Ok((byte - b'4').into()),
            b'A'..=b'Z' => Ok((byte - b'A' + 6).into()),
            _ => Err(Zbase32Error::BadByte(byte)),
        }
    }

    for i in 0..src.len() / 8 {
        let a = i * 8;
        let taxi: u64 = zb32_to_u64(src[a])?;
        let taxi = zb32_to_u64(src[a + 1])? | taxi << 5;
        let taxi = zb32_to_u64(src[a + 2])? | taxi << 5;
        let taxi = zb32_to_u64(src[a + 3])? | taxi << 5;
        let taxi = zb32_to_u64(src[a + 4])? | taxi << 5;
        let taxi = zb32_to_u64(src[a + 5])? | taxi << 5;
        let taxi = zb32_to_u64(src[a + 6])? | taxi << 5;
        let taxi = zb32_to_u64(src[a + 7])? | taxi << 5;

        let b = i * 5;
        dst[b] = (taxi >> 32) as u8;
        dst[b + 1] = (taxi >> 24) as u8;
        dst[b + 2] = (taxi >> 16) as u8;
        dst[b + 3] = (taxi >> 8) as u8;
        dst[b + 4] = taxi as u8;
    }
    Ok(())
}

/// Error when trying to decode a hex encoded [Hash](crate::Hash).
#[derive(Debug, PartialEq, Eq)]
pub enum HexError {
    /// The length in wrong
    BadLen(usize),

    /// Contains an invalid byte
    BadByte(u8),
}

/// Buffer containing the 320-bit (40-byte) BLAKE2b hash, with ConstantTimeEq.
///
/// # Examples
///
/// ```
/// use zf_zebrachain::Hash;
/// let hash = Hash::compute(b"hello, world");
/// ```
#[derive(Eq, Clone, Copy, PartialOrd, Ord)]
pub struct Hash {
    value: [u8; DIGEST],
}

impl Hash {
    /// Compute the 320-bit BLAKE2b hash of `input`, returning `Hash`.
    pub fn compute(input: &[u8]) -> Self {
        assert!(!input.is_empty());
        let mut hasher = Blake2b360::new();
        hasher.update(input);
        let output = hasher.finalize();
        Self::from_bytes(output.into())
    }

    /// Load from a slice
    pub fn from_slice(slice: &[u8]) -> Result<Self, core::array::TryFromSliceError> {
        Ok(Self::from_bytes(slice.try_into()?))
    }

    /// Create from bytes.
    pub const fn from_bytes(value: [u8; DIGEST]) -> Self {
        Self { value }
    }

    /// The raw bytes of the `Hash`.
    pub const fn as_bytes(&self) -> &[u8; DIGEST] {
        &self.value
    }

    /// Constant time check of whether every byte is a zero.
    pub fn is_zeros(&self) -> bool {
        // FIXME: Do this without comparing to another [u8; DIGEST]
        self.value.ct_eq(&[0; DIGEST]).into()
    }

    /// Decode a `Hash` from lowercase hexadecimal.
    pub fn from_hex(hex: impl AsRef<[u8]>) -> Result<Self, HexError> {
        // Totally copied from blake3::Hash::from_hex()
        fn hex_val(byte: u8) -> Result<u8, HexError> {
            match byte {
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                b'0'..=b'9' => Ok(byte - b'0'),
                _ => Err(HexError::BadByte(byte)),
            }
        }
        let hex_bytes: &[u8] = hex.as_ref();
        if hex_bytes.len() != HEXDIGEST {
            return Err(HexError::BadLen(hex_bytes.len()));
        }
        let mut hash_bytes: [u8; DIGEST] = [0; DIGEST];
        for i in 0..DIGEST {
            hash_bytes[i] = 16 * hex_val(hex_bytes[2 * i])? + hex_val(hex_bytes[2 * i + 1])?;
        }
        Ok(Self::from_bytes(hash_bytes))
    }

    /// Encode in lowercase hexidecimal
    pub fn to_hex(&self) -> arrayvec::ArrayString<HEXDIGEST> {
        // Totally copied from blake3::Hash.to_hex()
        let mut hex = arrayvec::ArrayString::new();
        let table = b"0123456789abcdef";
        for &b in self.value.iter() {
            hex.push(table[(b >> 4) as usize] as char);
            hex.push(table[(b & 0xf) as usize] as char);
        }
        hex
    }

    /// Decode Zbase32 encoded Hash.
    pub fn from_z32(src: &[u8]) -> Result<Self, Zbase32Error> {
        let mut dst = [0; DIGEST];
        zbase32_dec_into(src, &mut dst)?;
        Ok(Self::from_bytes(dst))
    }

    /// Encode in Zbase32.
    pub fn to_z32(&self) -> [u8; Z32DIGEST] {
        let mut z32 = [0; Z32DIGEST];
        zbase32_enc_into(&self.value, &mut z32);
        z32
    }

    /// Encode as Zbase32 String
    pub fn to_z32_string(&self) -> String {
        let mut z32 = vec![0; Z32DIGEST];
        zbase32_enc_into(&self.value, &mut z32);
        String::from_utf8(z32).unwrap()
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
        let z32 = self.to_z32_string();
        f.debug_tuple("Hash").field(&z32).finish()
    }
}

impl core::fmt::Display for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(&self.to_z32_string())
    }
}

/// A 384-bit (48-byte) root secret with ZeroizeOnDrop and ConstantTimeEq.
///
/// This value should not be fed directly into any cryptographic primitives. Instead, a derived
/// [SubSecret] should be used.  See [Secret::derive_sub_secret_256()],
/// [Secret::derive_sub_secret_192()].
///
/// # Examples
///
/// ```
/// use zf_zebrachain::Secret;
/// let secret = Secret::generate().unwrap();
/// let new_entropy = Secret::generate().unwrap();
/// let next_secret = secret.mix(&new_entropy);
/// ```
#[derive(Zeroize, ZeroizeOnDrop, Eq, Clone)]
pub struct Secret {
    value: [u8; SECRET],
}

impl Secret {
    /// Return a `Secret` with entropy from [getrandom::fill()].
    pub fn generate() -> Result<Self, EntropyError> {
        let mut buf = [0; SECRET];
        match getrandom::fill(&mut buf) {
            Ok(_) => Ok(Self::from_bytes(buf)),
            Err(err) => Err(EntropyError::new(err)),
        }
    }

    /// Load from a slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, core::array::TryFromSliceError> {
        Ok(Self::from_bytes(bytes.try_into()?))
    }

    /// Create a `Secret` from provided bytes.
    pub fn from_bytes(value: [u8; SECRET]) -> Self {
        Self { value }
    }

    /// The raw bytes of the `Secret`.
    pub fn as_bytes(&self) -> &[u8; SECRET] {
        &self.value
    }

    /// Constant time check of whether every byte is a zero.
    pub fn is_zeros(&self) -> bool {
        // FIXME: Do this without comparing to another [u8; SECRET]
        self.value.ct_eq(&[0; SECRET]).into()
    }

    /// Keyed hashing using BLAKE2b-384. The mix*() methods all use this.
    #[doc(hidden)]
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

    /// Mix new entropy with this secret to create the next secret.
    pub fn mix(&self, new_entropy: &Self) -> Self {
        self.keyed_hash(new_entropy.as_bytes())
    }

    /// Derive a new secret from this secret and context bytes.
    pub fn mix_with_context(&self, context: &[u8; CONTEXT]) -> Self {
        self.keyed_hash(context)
    }

    /// Derive a new secret from this secret and the bytes in `hash`.
    pub fn mix_with_hash(&self, hash: &Hash) -> Self {
        self.keyed_hash(hash.as_bytes())
    }

    /// Derive a 256-bit (32-byte) sub-secret from this secret, the block index, and context bytes.
    ///
    /// This is used for the XChaCha20Poly1305 key, the ed25519 seed, and the ML-DSA seed.
    pub fn derive_sub_secret_256(&self, block_index: u64, context: &[u8; CONTEXT]) -> SubSecret256 {
        let mut hasher = Blake2bMac256::new_with_salt_and_personal(
            self.as_bytes(),
            &block_index.to_le_bytes(),
            &[],
        )
        .unwrap();
        hasher.update(context);
        let output = hasher.finalize();
        SubSecret::from_bytes(output.into_bytes().into())
    }

    /// Derive a 192-bit (24-byte) sub-secret from this secret, the block index, and context bytes.
    ///
    /// This is used for the XChaCha20Poly1305 nonce.
    pub fn derive_sub_secret_192(&self, block_index: u64, context: &[u8; CONTEXT]) -> SubSecret192 {
        let mut hasher = Blake2bMac192::new_with_salt_and_personal(
            self.as_bytes(),
            &block_index.to_le_bytes(),
            &[],
        )
        .unwrap();
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

/// Simple buffer with ZeroizeOnDrop and ConstantTimeEq.
#[derive(Zeroize, ZeroizeOnDrop, Eq)]
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

impl<const N: usize> ConstantTimeEq for SubSecret<N> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.value.ct_eq(&other.value)
    }
}

impl<const N: usize> PartialEq for SubSecret<N> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<const N: usize> core::hash::Hash for SubSecret<N> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state)
    }
}

impl<const N: usize> core::fmt::Debug for SubSecret<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("SubSecret(<hidden>)")
    }
}

/// A 192-bit (24-byte) derived secret.
///
/// This is used for the XChaCha20Poly1305 nonce.
pub type SubSecret192 = SubSecret<24>;

/// A 256-bit (32-byte) derived secret.
///
/// This is used for the XChaCha20Poly1305 key, the ed25519 seed, and the ML-DSA seed.
pub type SubSecret256 = SubSecret<32>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhelpers::random_hash;
    use std::collections::HashSet;

    #[test]
    fn test_zbase32_enc_into() {
        let mut dst = [0; Z32DIGEST];
        zbase32_enc_into(&[0; DIGEST], &mut dst);
        assert_eq!(dst, [b'4'; Z32DIGEST]);
        zbase32_enc_into(&[255; DIGEST], &mut dst);
        assert_eq!(dst, [b'Z'; Z32DIGEST]);
    }

    #[test]
    fn test_zbase32_roundtrip() {
        for _ in 0..420 {
            let src = random_hash();
            let mut dst = [0; Z32DIGEST];
            zbase32_enc_into(src.as_bytes(), &mut dst);
            let mut tripped = [0; DIGEST];
            zbase32_dec_into(&dst, &mut tripped).unwrap();
            assert_eq!(src.as_bytes(), &tripped);
        }
    }

    #[test]
    fn test_argon2() {
        let password = b"hunter42";
        let salt = Secret::generate().unwrap();
        let mut buf = [0; SECRET];
        argon2::Argon2::default()
            .hash_password_into(password, salt.as_bytes(), &mut buf)
            .unwrap();
    }

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
            "9CP6OELE9CP6OELE9CP6OELE9CP6OELE9CP6OELE9CP6OELE9CP6OELE9CP6OELE9CP6OELE"
        );
    }

    #[test]
    fn test_hash_debug_fmt() {
        let hash = Hash::from_bytes([42; DIGEST]);
        assert_eq!(
            format!("{hash:?}"),
            "Hash(\"9CP6OELE9CP6OELE9CP6OELE9CP6OELE9CP6OELE9CP6OELE9CP6OELE9CP6OELE9CP6OELE\")"
        );
    }

    #[test]
    fn test_secret_debug_fmt() {
        let secret = Secret::from_bytes([42; SECRET]);
        assert_eq!(format!("{secret:?}"), "Secret(<hidden>)");
    }

    #[test]
    fn test_sub_secret_192_debug_fmt() {
        let secret = SubSecret192::from_bytes([42; 24]);
        assert_eq!(format!("{secret:?}"), "SubSecret(<hidden>)");
    }

    #[test]
    fn test_sub_secret_256_debug_fmt() {
        let secret = SubSecret256::from_bytes([42; 32]);
        assert_eq!(format!("{secret:?}"), "SubSecret(<hidden>)");
    }

    #[test]
    fn test_secret_mix_with_context() {
        let secret = Secret::from_bytes([7; SECRET]);

        let h = secret.mix_with_context(CONTEXT_SECRET);
        assert_eq!(
            h.as_bytes(),
            &[
                35, 198, 160, 225, 60, 140, 148, 63, 70, 67, 122, 93, 231, 105, 254, 64, 219, 221,
                66, 14, 76, 187, 106, 200, 46, 90, 244, 81, 96, 219, 191, 201, 184, 255, 113, 3,
                37, 237, 232, 95, 87, 165, 31, 230, 252, 134, 92, 215
            ]
        );

        let h = secret.mix_with_context(CONTEXT_SECRET_NEXT);
        assert_eq!(
            h.as_bytes(),
            &[
                224, 253, 204, 214, 205, 142, 89, 112, 92, 146, 146, 185, 145, 251, 167, 27, 49,
                38, 81, 141, 56, 236, 60, 220, 149, 168, 87, 57, 63, 55, 29, 87, 119, 179, 104,
                169, 108, 200, 241, 6, 164, 13, 58, 138, 179, 121, 106, 182
            ]
        );

        let secret = Secret::from_bytes([8; SECRET]);

        let h = secret.mix_with_context(CONTEXT_SECRET);
        assert_eq!(
            h.as_bytes(),
            &[
                86, 253, 101, 159, 9, 23, 4, 5, 221, 93, 250, 90, 85, 65, 200, 106, 251, 232, 49,
                128, 1, 26, 40, 121, 134, 49, 243, 54, 121, 199, 28, 232, 230, 110, 203, 12, 21,
                28, 195, 64, 49, 22, 218, 219, 234, 145, 219, 91
            ]
        );

        let h = secret.mix_with_context(CONTEXT_SECRET_NEXT);
        assert_eq!(
            h.as_bytes(),
            &[
                115, 28, 65, 249, 166, 179, 234, 167, 239, 54, 59, 82, 134, 83, 141, 37, 77, 166,
                77, 122, 179, 238, 91, 24, 185, 40, 69, 213, 197, 219, 134, 147, 66, 115, 41, 107,
                159, 26, 210, 122, 45, 128, 152, 254, 57, 212, 225, 198
            ]
        );
    }

    #[test]
    fn test_secret_derive_sub_secret_192() {
        let mut hset: HashSet<SubSecret192> = HashSet::new();
        for _ in 0..69 {
            let secret = Secret::generate().unwrap();
            for block_index in 0..420 {
                for context in [
                    CONTEXT_ED25519,
                    CONTEXT_ML_DSA,
                    CONTEXT_BLOCK_KEY,
                    CONTEXT_BLOCK_NONCE,
                ] {
                    let subsecret = secret.derive_sub_secret_192(block_index, context);
                    assert!(hset.insert(subsecret));
                }
            }
        }
        assert_eq!(hset.len(), 69 * 420 * 4);
    }

    #[test]
    fn test_secret_derive_sub_secret_256() {
        let mut hset: HashSet<SubSecret256> = HashSet::new();
        for _ in 0..69 {
            let secret = Secret::generate().unwrap();
            for block_index in 0..420 {
                for context in [
                    CONTEXT_ED25519,
                    CONTEXT_ML_DSA,
                    CONTEXT_BLOCK_KEY,
                    CONTEXT_BLOCK_NONCE,
                ] {
                    let subsecret = secret.derive_sub_secret_256(block_index, context);
                    assert!(hset.insert(subsecret));
                }
            }
        }
        assert_eq!(hset.len(), 69 * 420 * 4);
    }
}
