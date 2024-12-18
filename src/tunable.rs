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
pub const BLOCK: usize = DIGEST * 5 + SIGNATURE + PUBKEY;

pub const HASHABLE_RANGE: Range<usize> = DIGEST..BLOCK;
pub const SIGNABLE_RANGE: Range<usize> = DIGEST + SIGNATURE..BLOCK;

pub const HASH_RANGE: Range<usize> = 0..DIGEST;
pub const SIGNATURE_RANGE: Range<usize> = DIGEST..DIGEST + SIGNATURE;
pub const PUBKEY_RANGE: Range<usize> = DIGEST + SIGNATURE..DIGEST + SIGNATURE + PUBKEY;
pub const NEXT_PUBKEY_HASH_RANGE: Range<usize> = BLOCK - DIGEST * 4..BLOCK - DIGEST * 3;
pub const STATE_HASH_RANGE: Range<usize> = BLOCK - DIGEST * 3..BLOCK - DIGEST * 2;
pub const PREVIOUS_HASH_RANGE: Range<usize> = BLOCK - DIGEST * 2..BLOCK - DIGEST;
pub const CHAIN_HASH_RANGE: Range<usize> = BLOCK - DIGEST..BLOCK;

/*
A SecretBlock currently has 5 fields:

    HASH || SECRET || NEXT_SECRET || STATE_HASH || PREVIOUS_HASH
*/

pub const SECRET_BLOCK: usize = DIGEST * 5;
pub const SECRET_RANGE: Range<usize> = DIGEST..DIGEST * 2;
pub const NEXT_SECRET_RANGE: Range<usize> = DIGEST * 2..DIGEST * 3;
pub const SECRET_STATE_RANGE: Range<usize> = DIGEST * 3..DIGEST * 4;
pub const SECRET_PREVIOUS_RANGE: Range<usize> = DIGEST * 4..DIGEST * 5;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ranges() {
        assert_eq!(HASHABLE_RANGE, 32..256);
        assert_eq!(SIGNABLE_RANGE, 96..256);

        assert_eq!(HASH_RANGE, 0..32);
        assert_eq!(SIGNATURE_RANGE, 32..96);
        assert_eq!(PUBKEY_RANGE, 96..128);
        assert_eq!(NEXT_PUBKEY_HASH_RANGE, 128..160);
        assert_eq!(STATE_HASH_RANGE, 160..192);
        assert_eq!(PREVIOUS_HASH_RANGE, 192..224);
        assert_eq!(CHAIN_HASH_RANGE, 224..256);
    }
}
