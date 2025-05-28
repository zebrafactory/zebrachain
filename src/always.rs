//! Wire format ranges are defined here (good place to start).

use crate::hashing::{Hash, Secret};
use std::ops::Range;

/*
A Block has 8 fields:

    HASH || SIG || PUB || NEXT_PUB_HASH || PAYLOAD || INDEX || CHAIN_HASH || PREV_HASH
            ^^^^^^^^^^^^^^^^^^^^^^^^^^^               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
            From the `Seed`                           From the previous `BlockState`
Where:

    HASH = hash(SIG || PUB || NEXT_PUB_HASH || PAYLOAD || INDEX || CHAIN_HASH || PREV_HASH)

And where:

    SIG = sign(PUB || NEXT_PUB_HASH || PAYLOAD || INDEX || CHAIN_HASH || PREV_HASH)
*/

pub(crate) const PUB_ED25519: usize = 32;
pub(crate) const SIG_ED25519: usize = 64;
pub(crate) const PUB_MLDSA: usize = 1952;
pub(crate) const SIG_MLDSA: usize = 3309;

pub(crate) const PUB_MLDSA_RANGE: Range<usize> = 0..PUB_MLDSA;
pub(crate) const PUB_ED25519_RANGE: Range<usize> = PUB_MLDSA..PUB_MLDSA + PUB_ED25519;
pub(crate) const SIG_MLDSA_RANGE: Range<usize> = 0..SIG_MLDSA;
pub(crate) const SIG_ED25519_RANGE: Range<usize> = SIG_MLDSA..SIG_MLDSA + SIG_ED25519;

/// Size of hash output digest (32 bytes).
pub const DIGEST: usize = 32;

// Size of secret and next_secret
pub(crate) const SECRET: usize = 32;

// Size digest used in secret block
pub(crate) const SEC_DIGEST: usize = 32;

pub(crate) const SEED: usize = 2 * SECRET;
pub(crate) const SIGNATURE: usize = SIG_ED25519 + SIG_MLDSA;
pub(crate) const PUBKEY: usize = PUB_ED25519 + PUB_MLDSA;

pub(crate) const INDEX: usize = 8;
pub(crate) const TIME: usize = 16;

/// Size of the ZebraChain payload (48 bytes).
pub const PAYLOAD: usize = TIME + DIGEST;

/// Size of the ZebraChain block (5541 bytes).
pub const BLOCK: usize = (4 * DIGEST) + SIGNATURE + PUBKEY + PAYLOAD + INDEX;

pub(crate) const HASHABLE_RANGE: Range<usize> = DIGEST..BLOCK;
pub(crate) const SIGNABLE_RANGE: Range<usize> = DIGEST + SIGNATURE..BLOCK;
pub(crate) const SIGNABLE2_RANGE: Range<usize> = SIGNABLE_RANGE.start - SIG_ED25519..BLOCK;

const WIRE: [usize; 8] = [
    DIGEST,    // Block hash
    SIGNATURE, // ML-DSA + ed25519 signatures
    PUBKEY,    // ML-DSA + ed25519 public keys
    DIGEST,    // Hash of public key that will be used to sign next block
    PAYLOAD,   // Stuff to be signed
    INDEX,     // Block index
    DIGEST,    // Chain hash (hash of first block in chain)
    DIGEST,    // Previous block hash
];

const fn get_range(index: usize) -> Range<usize> {
    if index == 0 {
        0..WIRE[0]
    } else {
        let start = get_range(index - 1).end; // Can't use slice.iter().sum() in const fn
        start..start + WIRE[index]
    }
}

pub(crate) const HASH_RANGE: Range<usize> = get_range(0);
pub(crate) const SIGNATURE_RANGE: Range<usize> = get_range(1);
pub(crate) const PUBKEY_RANGE: Range<usize> = get_range(2);
pub(crate) const NEXT_PUBKEY_HASH_RANGE: Range<usize> = get_range(3);
pub(crate) const PAYLOAD_RANGE: Range<usize> = get_range(4);
pub(crate) const INDEX_RANGE: Range<usize> = get_range(5);
pub(crate) const CHAIN_HASH_RANGE: Range<usize> = get_range(6);
pub(crate) const PREVIOUS_HASH_RANGE: Range<usize> = get_range(7);

/*
A SecretBlock currently has 6 fields:

    HASH || PUBLIC_HASH || SEED || PAYLOAD || INDEX || PREVIOUS_HASH
                                              ^^^^^^^^^^^^^^^^^^^^^^
                                              From the previous block
*/

pub(crate) const SECRET_BLOCK: usize = 5 * SEC_DIGEST + PAYLOAD + INDEX;
pub(crate) const SECRET_BLOCK_AEAD: usize = SECRET_BLOCK + 16;

const SEC_WIRE: [usize; 6] = [
    SEC_DIGEST, // Block hash
    DIGEST,     // Public block hash
    SEED,       // secret + next_secret
    PAYLOAD,    // Stuff to be signed
    INDEX,      // Block index
    SEC_DIGEST, // Previous block hash
];

const fn get_secrange(index: usize) -> Range<usize> {
    if index == 0 {
        0..SEC_WIRE[0]
    } else {
        let start = get_secrange(index - 1).end; // Can't use slice.iter().sum() in const fn
        start..start + SEC_WIRE[index]
    }
}

pub(crate) const SEC_HASH_RANGE: Range<usize> = get_secrange(0);
pub(crate) const SEC_PUBLIC_HASH_RANGE: Range<usize> = get_secrange(1);
pub(crate) const SEC_SEED_RANGE: Range<usize> = get_secrange(2);
pub(crate) const SEC_PAYLOAD_RANGE: Range<usize> = get_secrange(3);
pub(crate) const SEC_INDEX_RANGE: Range<usize> = get_secrange(4);
pub(crate) const SEC_PREV_HASH_RANGE: Range<usize> = get_secrange(5);

pub(crate) const SEC_HASHABLE_RANGE: Range<usize> = SEC_DIGEST..SECRET_BLOCK;

pub(crate) const BLOCK_READ_BUF: usize = BLOCK * 64;
pub(crate) const SECRET_BLOCK_AEAD_READ_BUF: usize = SECRET_BLOCK_AEAD * 64;

pub(crate) static CONTEXT_SECRET: &str =
    "ed149ef77826374035fd3a1e2c1bf3b39539333d5a8bc1f7e788736430efc7f2";
pub(crate) static CONTEXT_SECRET_NEXT: &str =
    "a0ec84dd51dabc0cfb7f61c936c8577c15982715b77ed5d6582cb01108769831";
pub(crate) static CONTEXT_ED25519: &str =
    "e3481172dcedab349a13152e9d002494f1ae292c868e049d93926c3a58a48408";
pub(crate) static CONTEXT_ML_DSA: &str =
    "e665ee96123e46d74e76dc53bdc64df06d72c238d574b7c153305f5e63063350";
//pub(crate) static CONTEXT_SLH_DSA: &str =
//    "b5de7bead4cac0fb4fe60cbb2ef31cb2c0590adb10f0764769cd5b0e0d7d11c1";
pub(crate) static CONTEXT_STORE_KEY: &str =
    "0179f9dd9cb5b0af47079d3a102872a32744b7f7aa8a5f22f7c0a16ba8549601";
pub(crate) static CONTEXT_STORE_NONCE: &str =
    "dc49809016fca0a126c5df6d373e90c48683e664ecba0440ae59523d93e13515";

pub(crate) static SIGNING_CXT_ML_DSA: &[u8] =
    b"270973c068ca5b0188c0e0b89f286d1a8c6a3b3c176aa07b3ae3a519fd65032f";
//pub(crate) static SIGNING_CXT_SLH_DSA: &[u8] =
//    b"b71cd1500453530f76d0a4e47863c69bb4842a42ba088532d58d11c149489853";

pub(crate) const ZERO_HASH: Hash = Hash::from_bytes([0; DIGEST]);

#[inline]
pub(crate) fn get_hash(buf: &[u8], range: Range<usize>) -> Hash {
    Hash::from_bytes(buf[range].try_into().unwrap())
}

#[inline]
pub(crate) fn set_hash(buf: &mut [u8], range: Range<usize>, value: &Hash) {
    buf[range].copy_from_slice(value.as_bytes());
}

#[inline]
pub(crate) fn get_secret(buf: &[u8], range: Range<usize>) -> Secret {
    Secret::from_slice(&buf[range]).unwrap()
}

#[inline]
pub(crate) fn set_secret(buf: &mut [u8], range: Range<usize>, value: &Secret) {
    buf[range].copy_from_slice(value.as_bytes());
}

#[inline]
pub(crate) fn get_u64(buf: &[u8], range: Range<usize>) -> u64 {
    u64::from_le_bytes(buf[range].try_into().unwrap())
}

#[inline]
pub(crate) fn set_u64(buf: &mut [u8], range: Range<usize>, value: u64) {
    buf[range].copy_from_slice(&value.to_le_bytes());
}

#[inline]
pub(crate) fn get_u128(buf: &[u8], range: Range<usize>) -> u128 {
    u128::from_le_bytes(buf[range].try_into().unwrap())
}

#[inline]
pub(crate) fn set_u128(buf: &mut [u8], range: Range<usize>, value: u128) {
    buf[range].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ranges() {
        assert_eq!(HASHABLE_RANGE, 32..5541);
        assert_eq!(SIGNABLE_RANGE, 3405..5541);
        assert_eq!(SIGNABLE2_RANGE, 3341..5541);

        assert_eq!(HASH_RANGE, 0..32);

        assert_eq!(SIGNATURE_RANGE, 32..3405);
        assert_eq!(PUBKEY_RANGE, 3405..5389);
        assert_eq!(NEXT_PUBKEY_HASH_RANGE, 5389..5421);

        assert_eq!(PAYLOAD_RANGE, 5421..5469);

        assert_eq!(INDEX_RANGE, 5469..5477);
        assert_eq!(CHAIN_HASH_RANGE, 5477..5509);
        assert_eq!(PREVIOUS_HASH_RANGE, 5509..5541);

        assert_eq!(HASHABLE_RANGE.end, BLOCK);
        assert_eq!(SIGNABLE_RANGE.end, BLOCK);
        assert_eq!(PREVIOUS_HASH_RANGE.end, BLOCK);
    }

    #[test]
    fn test_sec_ranges() {
        assert_eq!(SEC_HASH_RANGE, 0..32);
        assert_eq!(SEC_PUBLIC_HASH_RANGE, 32..64);
        assert_eq!(SEC_SEED_RANGE, 64..128);
        assert_eq!(SEC_PAYLOAD_RANGE, 128..176);
        assert_eq!(SEC_INDEX_RANGE, 176..184);
        assert_eq!(SEC_PREV_HASH_RANGE, 184..216);
        assert_eq!(SEC_PREV_HASH_RANGE.end, SECRET_BLOCK);
    }
}
