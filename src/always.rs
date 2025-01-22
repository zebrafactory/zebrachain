//! Wire format ranges are defined here (good place to start).

use std::ops::Range;

/*
A Block has 9 fields (currently):

    HASH || SIG || PUBKEY || NEXT_PUBKEY_HASH || INDEX || PERMISSION_HASH || STATE_HASH || PREVIOUS_HASH  || CHAIN_HASH

Where:

    HASH = hash(SIG || PUBKEY || NEXT_PUBKEY_HASH || INDEX ||  PERMISSION_HASH || STATE_HASH || PREVIOUS_HASH  || CHAIN_HASH)

And where:

    SIG = sign(PUBKEY || NEXT_PUBKEY_HASH || INDEX ||  PERMISSION_HASH || STATE_HASH || PREVIOUS_HASH  || CHAIN_HASH)

A TIMESTAMP will likely be added.
*/

pub const PUB_ED25519: usize = 32;
pub const SIG_ED25519: usize = 64;
pub const PUB_DILITHIUM: usize = 1952;
pub const SIG_DILITHIUM: usize = 3293;

pub const PUB_DILITHIUM_RANGE: Range<usize> = 0..PUB_DILITHIUM;
pub const PUB_ED25519_RANGE: Range<usize> = PUB_DILITHIUM..PUB_DILITHIUM + PUB_ED25519;
pub const SIG_DILITHIUM_RANGE: Range<usize> = 0..SIG_DILITHIUM;
pub const SIG_ED25519_RANGE: Range<usize> = SIG_DILITHIUM..SIG_DILITHIUM + SIG_ED25519;

pub const DIGEST: usize = 32;
pub const SIGNATURE: usize = 64; // Need more Dilithium, Captian!
pub const PUBKEY: usize = 32; // STILL need more Dilithium, Captian!!!
pub const BLOCK: usize = DIGEST * 6 + SIGNATURE + PUBKEY + 8;

pub const HASHABLE_RANGE: Range<usize> = DIGEST..BLOCK;
pub const SIGNABLE_RANGE: Range<usize> = DIGEST + SIGNATURE..BLOCK;

pub const HASH_RANGE: Range<usize> = 0..DIGEST;
pub const SIGNATURE_RANGE: Range<usize> = DIGEST..DIGEST + SIGNATURE;
pub const PUBKEY_RANGE: Range<usize> = SIGNATURE_RANGE.end..SIGNATURE_RANGE.end + PUBKEY;
pub const NEXT_PUBKEY_HASH_RANGE: Range<usize> = PUBKEY_RANGE.end..PUBKEY_RANGE.end + DIGEST;
pub const INDEX_RANGE: Range<usize> = NEXT_PUBKEY_HASH_RANGE.end..NEXT_PUBKEY_HASH_RANGE.end + 8;

pub const PERMISSION_HASH_RANGE: Range<usize> = BLOCK - DIGEST * 4..BLOCK - DIGEST * 3;
pub const STATE_HASH_RANGE: Range<usize> = BLOCK - DIGEST * 3..BLOCK - DIGEST * 2;
pub const PREVIOUS_HASH_RANGE: Range<usize> = BLOCK - DIGEST * 2..BLOCK - DIGEST;
pub const CHAIN_HASH_RANGE: Range<usize> = BLOCK - DIGEST..BLOCK;

/*
A SecretBlock currently has 6 fields:

    HASH || SECRET || NEXT_SECRET || PERMISSION_HASH || STATE_HASH || PREVIOUS_HASH
*/

pub const SECRET_BLOCK: usize = DIGEST * 6;

pub static SECRET_CONTEXT: &str =
    "ed149ef77826374035fd3a1e2c1bf3b39539333d5a8bc1f7e788736430efc7f2";

pub static NEXT_SECRET_CONTEXT: &str =
    "a0ec84dd51dabc0cfb7f61c936c8577c15982715b77ed5d6582cb01108769831";

pub static ED25519_CONTEXT: &str =
    "e3481172dcedab349a13152e9d002494f1ae292c868e049d93926c3a58a48408";

pub static DILITHIUM_CONTEXT: &str =
    "e665ee96123e46d74e76dc53bdc64df06d72c238d574b7c153305f5e63063350";

pub static SPHINCSPLUS_CONTEXT: &str =
    "b5de7bead4cac0fb4fe60cbb2ef31cb2c0590adb10f0764769cd5b0e0d7d11c1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ranges() {
        assert_eq!(HASHABLE_RANGE, 32..296);
        assert_eq!(SIGNABLE_RANGE, 96..296);

        assert_eq!(HASH_RANGE, 0..32);
        assert_eq!(SIGNATURE_RANGE, 32..96);
        assert_eq!(PUBKEY_RANGE, 96..128);
        assert_eq!(NEXT_PUBKEY_HASH_RANGE, 128..160);
        assert_eq!(INDEX_RANGE, 160..168);
        assert_eq!(PERMISSION_HASH_RANGE, 168..200);
        assert_eq!(STATE_HASH_RANGE, 200..232);
        assert_eq!(PREVIOUS_HASH_RANGE, 232..264);
        assert_eq!(CHAIN_HASH_RANGE, 264..296);
    }
}
