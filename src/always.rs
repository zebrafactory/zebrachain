//! Wire format ranges are defined here (good place to start).

use blake3::Hash;
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

pub const PUB_ED25519: usize = 32;
pub const SIG_ED25519: usize = 64;
pub const PUB_MLDSA: usize = 1952;
pub const SIG_MLDSA: usize = 3309;

pub const PUB_MLDSA_RANGE: Range<usize> = 0..PUB_MLDSA;
pub const PUB_ED25519_RANGE: Range<usize> = PUB_MLDSA..PUB_MLDSA + PUB_ED25519;
pub const SIG_MLDSA_RANGE: Range<usize> = 0..SIG_MLDSA;
pub const SIG_ED25519_RANGE: Range<usize> = SIG_MLDSA..SIG_MLDSA + SIG_ED25519;

pub const DIGEST: usize = 32;
pub const SEED: usize = 2 * DIGEST;
pub const SIGNATURE: usize = SIG_ED25519 + SIG_MLDSA;
pub const PUBKEY: usize = PUB_ED25519 + PUB_MLDSA;

/// Size of the (non-configurable) ZebraChain payload (40 bytes).
pub const PAYLOAD: usize = 8 + DIGEST;

/// Size of the (non-configurable) ZebraChain block (5533 bytes).
pub const BLOCK: usize = (4 * DIGEST) + SIGNATURE + PUBKEY + PAYLOAD + 8;

pub const HASHABLE_RANGE: Range<usize> = DIGEST..BLOCK;
pub const SIGNABLE_RANGE: Range<usize> = DIGEST + SIGNATURE..BLOCK;
pub const SIGNABLE2_RANGE: Range<usize> = SIGNABLE_RANGE.start - SIG_ED25519..BLOCK;

const WIRE: [usize; 8] = [
    DIGEST,    // Block hash
    SIGNATURE, // ML-DSA + ed25519 signatures
    PUBKEY,    // ML-DSA + ed25519 public keys
    DIGEST,    // Hash of public key that will be used to sign next block
    PAYLOAD,   // Stuff to be signed
    8,         // Block index
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

pub const HASH_RANGE: Range<usize> = get_range(0);
pub const SIGNATURE_RANGE: Range<usize> = get_range(1);
pub const PUBKEY_RANGE: Range<usize> = get_range(2);
pub const NEXT_PUBKEY_HASH_RANGE: Range<usize> = get_range(3);
pub const PAYLOAD_RANGE: Range<usize> = get_range(4);
pub const INDEX_RANGE: Range<usize> = get_range(5);
pub const CHAIN_HASH_RANGE: Range<usize> = get_range(6);
pub const PREVIOUS_HASH_RANGE: Range<usize> = get_range(7);

/*
A SecretBlock currently has 6 fields:

    HASH || PUBLIC_HASH || SEED || PAYLOAD || INDEX || PREVIOUS_HASH
                                              ^^^^^^^^^^^^^^^^^^^^^^
                                              From the previous block
*/

pub const SECRET_BLOCK: usize = 5 * DIGEST + PAYLOAD + 8;
pub const SECRET_BLOCK_AEAD: usize = SECRET_BLOCK + 16;

const SECWIRE: [usize; 6] = [
    DIGEST,  // Block hash
    DIGEST,  // Public block hash
    SEED,    // secret + next_secret
    PAYLOAD, // Stuff to be signed
    8,       // Block index
    DIGEST,  // Previous block hash
];

const fn get_secrange(index: usize) -> Range<usize> {
    if index == 0 {
        0..SECWIRE[0]
    } else {
        let start = get_secrange(index - 1).end; // Can't use slice.iter().sum() in const fn
        start..start + SECWIRE[index]
    }
}

pub const SEC_HASH_RANGE: Range<usize> = get_secrange(0);
pub const SEC_PUBLIC_HASH_RANGE: Range<usize> = get_secrange(1);
pub const SEC_SEED_RANGE: Range<usize> = get_secrange(2);
pub const SEC_PAYLOAD_RANGE: Range<usize> = get_secrange(3);
pub const SEC_INDEX_RANGE: Range<usize> = get_secrange(4);
pub const SEC_PREV_HASH_RANGE: Range<usize> = get_secrange(5);

pub const BLOCK_READ_BUF: usize = BLOCK * 64;
pub const SECRET_BLOCK_AEAD_READ_BUF: usize = SECRET_BLOCK_AEAD * 64;

pub static CONTEXT_SECRET: &str =
    "ed149ef77826374035fd3a1e2c1bf3b39539333d5a8bc1f7e788736430efc7f2";
pub static CONTEXT_SECRET_NEXT: &str =
    "a0ec84dd51dabc0cfb7f61c936c8577c15982715b77ed5d6582cb01108769831";
pub static CONTEXT_ED25519: &str =
    "e3481172dcedab349a13152e9d002494f1ae292c868e049d93926c3a58a48408";
pub static CONTEXT_ML_DSA: &str =
    "e665ee96123e46d74e76dc53bdc64df06d72c238d574b7c153305f5e63063350";
//pub static CONTEXT_SLH_DSA: &str =
//    "b5de7bead4cac0fb4fe60cbb2ef31cb2c0590adb10f0764769cd5b0e0d7d11c1";
pub static CONTEXT_STORE_KEY: &str =
    "0179f9dd9cb5b0af47079d3a102872a32744b7f7aa8a5f22f7c0a16ba8549601";
pub static CONTEXT_STORE_NONCE: &str =
    "dc49809016fca0a126c5df6d373e90c48683e664ecba0440ae59523d93e13515";

#[inline]
pub(crate) fn get_hash(buf: &[u8], range: Range<usize>) -> Hash {
    Hash::from_bytes(buf[range].try_into().unwrap())
}

#[inline]
pub(crate) fn set_hash(buf: &mut [u8], range: Range<usize>, value: &Hash) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ranges() {
        assert_eq!(HASHABLE_RANGE, 32..5533);
        assert_eq!(SIGNABLE_RANGE, 3405..5533);
        assert_eq!(SIGNABLE2_RANGE, 3341..5533);

        assert_eq!(HASH_RANGE, 0..32);

        assert_eq!(SIGNATURE_RANGE, 32..3405);
        assert_eq!(PUBKEY_RANGE, 3405..5389);
        assert_eq!(NEXT_PUBKEY_HASH_RANGE, 5389..5421);

        assert_eq!(PAYLOAD_RANGE, 5421..5461);

        assert_eq!(INDEX_RANGE, 5461..5469);
        assert_eq!(CHAIN_HASH_RANGE, 5469..5501);
        assert_eq!(PREVIOUS_HASH_RANGE, 5501..5533);

        assert_eq!(HASHABLE_RANGE.end, BLOCK);
        assert_eq!(SIGNABLE_RANGE.end, BLOCK);
        assert_eq!(PREVIOUS_HASH_RANGE.end, BLOCK);
    }

    #[test]
    fn test_sec_ranges() {
        assert_eq!(SEC_HASH_RANGE, 0..32);
        assert_eq!(SEC_PUBLIC_HASH_RANGE, 32..64);
        assert_eq!(SEC_SEED_RANGE, 64..128);
        assert_eq!(SEC_PAYLOAD_RANGE, 128..168);
        assert_eq!(SEC_INDEX_RANGE, 168..176);
        assert_eq!(SEC_PREV_HASH_RANGE, 176..208);
        assert_eq!(SEC_PREV_HASH_RANGE.end, SECRET_BLOCK);
    }
}
