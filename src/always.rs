use crate::{Hash, Secret};
use core::ops::Range;
use hex_literal::hex;

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

// FIXME: The remaining issue in finalizing the non-configurable "heavy" version of the protocol
// is ML-DSA 44 vs 65 (currently 44 is used). ML-DSA-65 is a nice middle of the road choice.
// But PQC signatures are huge and NIST required security for up to 2^64 signature (a rather large
// number). ZebraChain is bonkers conservative in that it only makes a single signature per
// keypair. Because of this, ML-DSA-44 is still quite conservative for ZebraChain (whereas if
// multiple signatures were made per keypair, we'd probably want to use ML-DSA-65).

// ML-DSA-44
pub(crate) const PUB_MLDSA: usize = 1312;
pub(crate) const SIG_MLDSA: usize = 2420;

// FIXME: once the protocol is configurable, we will support 65 also.
// ML-DSA-65
//pub(crate) const PUB_MLDSA: usize = 1952;
//pub(crate) const SIG_MLDSA: usize = 3309;

// FIXME: once the protocol is configurable, we will support 87 also... but for now, too big!
// ML-DSA-87
//pub(crate) const PUB_MLDSA: usize = 2529;
//pub(crate) const SIG_MLDSA: usize = 4627;

pub(crate) const PUB_MLDSA_RANGE: Range<usize> = 0..PUB_MLDSA;
pub(crate) const PUB_ED25519_RANGE: Range<usize> = PUB_MLDSA..PUB_MLDSA + PUB_ED25519;
pub(crate) const SIG_MLDSA_RANGE: Range<usize> = 0..SIG_MLDSA;
pub(crate) const SIG_ED25519_RANGE: Range<usize> = SIG_MLDSA..SIG_MLDSA + SIG_ED25519;

/// Size of hash output digest (45 bytes).
pub const DIGEST: usize = 45;

/// Size of hex-encoded hash (90 bytes).
pub const HEXDIGEST: usize = DIGEST * 2;

/// Size of Zbase32-encoded hash (72 bytes).
pub const Z32DIGEST: usize = DIGEST * 8 / 5;

/// Size of secrets (48 bytes)
pub const SECRET: usize = 48;

/// Size of context bytes (48 bytes)
pub const CONTEXT: usize = 48;

pub(crate) const SEED: usize = 2 * SECRET;
pub(crate) const SIGNATURE: usize = SIG_ED25519 + SIG_MLDSA;
pub(crate) const PUBKEY: usize = PUB_ED25519 + PUB_MLDSA;

pub(crate) const INDEX: usize = 8;
pub(crate) const TIME: usize = 8;

/// Size of the ZebraChain payload (48 bytes).
pub const PAYLOAD: usize = TIME + DIGEST;

/// Size of the ZebraChain block (4069 bytes).
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

/// Size of the decrypted secret block (292 bytes).
pub const SECRET_BLOCK: usize = 3 * DIGEST + SEED + PAYLOAD + INDEX;

/// Size of header at start of secret chain (88 bytes).
pub const SECRET_CHAIN_HEADER: usize = DIGEST + SECRET;

/// Size of the encrypted secret block (308 bytes) [this is the size on disk].
///
/// This is larger than [SECRET_BLOCK] because it includes the 16-byte Poly1305 authentication tag.
pub const SECRET_BLOCK_AEAD: usize = SECRET_BLOCK + 16;

const SEC_WIRE: [usize; 6] = [
    DIGEST,  // Block hash
    DIGEST,  // Public block hash
    SEED,    // secret + next_secret
    PAYLOAD, // Stuff to be signed
    INDEX,   // Block index
    DIGEST,  // Previous block hash
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

pub(crate) const SEC_HASHABLE_RANGE: Range<usize> = DIGEST..SECRET_BLOCK;

pub(crate) const BLOCK_READ_BUF: usize = 128 * 1024;
pub(crate) const SECRET_BLOCK_AEAD_READ_BUF: usize = 128 * 1024;

pub(crate) static CONTEXT_SECRET: &[u8; CONTEXT] = &hex!(
    "e4bc91ef0f7db22dfce22bc884f08f95ba16e61a0877071463db33282e98a2c3a2874901005be7cbed8f1313ceee28aa"
);
pub(crate) static CONTEXT_SECRET_NEXT: &[u8; CONTEXT] = &hex!(
    "5d4daadccb9519789aaaceab0586cc225016569aa0fa81028728f6bd24822cd45844d1d0c902ea0b2830202037f0d475"
);
pub(crate) static CONTEXT_ED25519: &[u8; CONTEXT] = &hex!(
    "34b6e6e4457630b111cba14c35d6586cbebd70a1b41aa87b89bb9bc2443d7b8d480d2e60e8427b662d72f72b8f603325"
);
pub(crate) static CONTEXT_ML_DSA: &[u8; CONTEXT] = &hex!(
    "8e0586f64a7d87360bd1898745f9e8e367b9d8b292c717d915f61f9eac1599b117d957dc5458bfb2f4bdfc69fafd1bfe"
);
//pub(crate) static CONTEXT_SLH_DSA: &[u8; CONTEXT] =
//    &hex!("1ce7f9e27feffbb8d02bb00906d27ccb90614c35c7b9b3c2cff8e7ce8ef8f19e7df3b3f3140cf009fbee85e2b19ec77c");
pub(crate) static CONTEXT_CHAIN_SALT: &[u8; CONTEXT] = &hex!(
    "1ed15c558923eea0d39e21e29142a8837a215e7cf63d6cb88c3caefb4a31ef91c0f2f6489b2c7f9ad80b95458f0fefad"
);
pub(crate) static CONTEXT_BLOCK_KEY: &[u8; CONTEXT] = &hex!(
    "f5c4428f694529e8139c825044e130dfd54182b8324142a3ea03b13085d83c63a01533f3ba4ddcd3835beaf086dc0d8b"
);
pub(crate) static CONTEXT_BLOCK_NONCE: &[u8; CONTEXT] = &hex!(
    "bb242d2282ebdd5db4c9abf70eb40830029d2c665013e946f58614912b97e199c62e5e02b57745a530d41796d6199d14"
);

pub(crate) static SIGNING_CXT_ML_DSA: &[u8; 32] =
    &hex!("270973c068ca5b0188c0e0b89f286d1a8c6a3b3c176aa07b3ae3a519fd65032f");
//pub(crate) static SIGNING_CXT_SLH_DSA: &[u8] =
//    b"b71cd1500453530f76d0a4e47863c69bb4842a42ba088532d58d11c149489853";

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ranges() {
        assert_eq!(HASHABLE_RANGE, 45..4069);
        assert_eq!(SIGNABLE_RANGE, 2529..4069);
        assert_eq!(SIGNABLE2_RANGE, 2465..4069);

        assert_eq!(HASH_RANGE, 0..45);

        assert_eq!(SIGNATURE_RANGE, 45..2529);
        assert_eq!(PUBKEY_RANGE, 2529..3873);
        assert_eq!(NEXT_PUBKEY_HASH_RANGE, 3873..3918);

        assert_eq!(PAYLOAD_RANGE, 3918..3971);

        assert_eq!(INDEX_RANGE, 3971..3979);
        assert_eq!(CHAIN_HASH_RANGE, 3979..4024);
        assert_eq!(PREVIOUS_HASH_RANGE, 4024..4069);

        assert_eq!(HASHABLE_RANGE.end, BLOCK);
        assert_eq!(SIGNABLE_RANGE.end, BLOCK);
        assert_eq!(PREVIOUS_HASH_RANGE.end, BLOCK);
    }

    #[test]
    fn test_sec_ranges() {
        assert_eq!(SEC_HASHABLE_RANGE, 45..292);

        assert_eq!(SEC_HASH_RANGE, 0..45);
        assert_eq!(SEC_PUBLIC_HASH_RANGE, 45..90);
        assert_eq!(SEC_SEED_RANGE, 90..186);
        assert_eq!(SEC_PAYLOAD_RANGE, 186..239);
        assert_eq!(SEC_INDEX_RANGE, 239..247);
        assert_eq!(SEC_PREV_HASH_RANGE, 247..292);
        assert_eq!(SEC_PREV_HASH_RANGE.end, SECRET_BLOCK);

        assert_eq!(SECRET_BLOCK_AEAD, 308);
    }
}
