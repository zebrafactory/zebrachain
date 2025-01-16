//! Wire format ranges are defined here (good place to start).

use std::ops::Range;

/*
A Block has 7 fields (currently):

    HASH || SIGNATURE || PUBKEY || NEXT_PUBKEY_HASH || STATE_HASH || PREVIOUS_HASH  || CHAIN_HASH

Where:

    HASH = hash(SIGNATURE || PUBKEY || NEXT_PUBKEY_HASH || STATE_HASH || PREVIOUS_HASH  || CHAIN_HASH)

And where:

    SIGNATURE = sign(PUBKEY || NEXT_PUBKEY_HASH || STATE_HASH || PREVIOUS_HASH  || CHAIN_HASH)

A COUNTER and TIMESTAMP will likely be added.
*/

pub const DIGEST: usize = 32;
pub const SIGNATURE: usize = 64; // Need more Dilithium, Captian!
pub const PUBKEY: usize = 32; // STILL need more Dilithium, Captian!!!
pub const BLOCK: usize = DIGEST * 6 + SIGNATURE + PUBKEY;

pub const HASHABLE_RANGE: Range<usize> = DIGEST..BLOCK;
pub const SIGNABLE_RANGE: Range<usize> = DIGEST + SIGNATURE..BLOCK;

pub const HASH_RANGE: Range<usize> = 0..DIGEST;
pub const SIGNATURE_RANGE: Range<usize> = DIGEST..DIGEST + SIGNATURE;
pub const PUBKEY_RANGE: Range<usize> = DIGEST + SIGNATURE..DIGEST + SIGNATURE + PUBKEY;

pub const NEXT_PUBKEY_HASH_RANGE: Range<usize> = BLOCK - DIGEST * 5..BLOCK - DIGEST * 4;
pub const PERMISSION_HASH_RANGE: Range<usize> = BLOCK - DIGEST * 4..BLOCK - DIGEST * 3;
pub const STATE_HASH_RANGE: Range<usize> = BLOCK - DIGEST * 3..BLOCK - DIGEST * 2;
pub const PREVIOUS_HASH_RANGE: Range<usize> = BLOCK - DIGEST * 2..BLOCK - DIGEST;
pub const CHAIN_HASH_RANGE: Range<usize> = BLOCK - DIGEST..BLOCK;

/*
A SecretBlock currently has 5 fields:

    HASH || SECRET || NEXT_SECRET || STATE_HASH || PREVIOUS_HASH
*/

pub const SECRET_BLOCK: usize = DIGEST * 5;

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
        assert_eq!(HASHABLE_RANGE, 32..288);
        assert_eq!(SIGNABLE_RANGE, 96..288);

        assert_eq!(HASH_RANGE, 0..32);
        assert_eq!(SIGNATURE_RANGE, 32..96);
        assert_eq!(PUBKEY_RANGE, 96..128);
        assert_eq!(NEXT_PUBKEY_HASH_RANGE, 128..160);
        assert_eq!(PERMISSION_HASH_RANGE, 160..192);
        assert_eq!(STATE_HASH_RANGE, 192..224);
        assert_eq!(PREVIOUS_HASH_RANGE, 224..256);
        assert_eq!(CHAIN_HASH_RANGE, 256..288);
    }
}
