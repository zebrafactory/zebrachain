//! Wire format ranges are defined here (good place to start).

use std::ops::Range;

/*
A Block has 10 fields (actually, 9 currently, so FIXME):

    HASH || SIG || PUB || NEXT_PUB_HASH || TIME || AUTH_HASH || STATE_HASH || INDEX || PREV_HASH || CHAIN_HASH
            ^^^^^^^^^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
            From the `Seed`                From the `SigningRequest`          From the previous `BlockState`
Where:

    HASH = hash(SIG || PUB || NEXT_PUB_HASH || TIME || AUTH_HASH || STATE_HASH || INDEX || PREV_HASH || CHAIN_HASH)
                ^^^^^^^^^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

And where:

    SIG = sign(PUB || NEXT_PUB_HASH || TIME || AUTH_HASH || STATE_HASH || INDEX || PREV_HASH || CHAIN_HASH)
                                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

FIXME: Current wire format lacks TIME and has INDEX in a different position.
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
pub const SIGNATURE: usize = SIG_ED25519 + SIG_DILITHIUM;
pub const PUBKEY: usize = PUB_ED25519 + PUB_DILITHIUM;
pub const BLOCK: usize = DIGEST * 6 + SIGNATURE + PUBKEY + 8;

pub const HASHABLE_RANGE: Range<usize> = DIGEST..BLOCK;
pub const SIGNABLE_RANGE: Range<usize> = DIGEST + SIGNATURE..BLOCK;

pub const WIRE: [usize; 9] = [
    DIGEST,    // Block hash
    SIGNATURE, // Dilithium + ed25519 signatures
    PUBKEY,    // Dilithium + ed25519 public keys
    DIGEST,    // Hash of next public key
    8,         // Block index (FIXME: make this the Time field)
    DIGEST,    // AUTH-entication, AUTH-orization hash
    DIGEST,    // State hash
    //8,         // Block index (FIXME: add another 8 bytes, put Index here
    DIGEST, // Previous block hash
    DIGEST, // Chain hash
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
pub const INDEX_RANGE: Range<usize> = get_range(4);
pub const AUTH_HASH_RANGE: Range<usize> = get_range(5);
pub const STATE_HASH_RANGE: Range<usize> = get_range(6);
pub const PREVIOUS_HASH_RANGE: Range<usize> = get_range(7);
pub const CHAIN_HASH_RANGE: Range<usize> = get_range(8);

/*
A SecretBlock currently has 6 fields:

    HASH || SECRET || NEXT_SECRET || AUTH_HASH || STATE_HASH || PREVIOUS_HASH
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
        assert_eq!(HASHABLE_RANGE, 32..5541);
        assert_eq!(SIGNABLE_RANGE, 3389..5541);

        assert_eq!(HASH_RANGE, 0..32);
        assert_eq!(SIGNATURE_RANGE, 32..3389);
        assert_eq!(PUBKEY_RANGE, 3389..5373);
        assert_eq!(NEXT_PUBKEY_HASH_RANGE, 5373..5405);
        assert_eq!(INDEX_RANGE, 5405..5413);
        assert_eq!(AUTH_HASH_RANGE, 5413..5445);
        assert_eq!(STATE_HASH_RANGE, 5445..5477);
        assert_eq!(PREVIOUS_HASH_RANGE, 5477..5509);
        assert_eq!(CHAIN_HASH_RANGE, 5509..5541);
    }

    #[test]
    fn test_get_range() {
        assert_eq!(get_range(0), 0..32);
        assert_eq!(get_range(1), 32..3389);
        assert_eq!(get_range(2), 3389..5373);
        assert_eq!(get_range(3), 5373..5405);
    }
}
