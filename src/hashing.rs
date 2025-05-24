/// Type used for hashes in public chain
pub type Hash = blake3::Hash;

/// Type used for secret block hash in secret chain
pub type SecHash = blake3::Hash;

/// A secret buffer with constant time comparison and zeroize.
///
/// This currently is just an alias for [blake3::Hash] because it gives us the features we need.
/// Eventually we should use separate types and abstractions for the notion of a Secret buffer vs
/// a Hash buffer as they will almost certainly need to differ in some configurations.
pub type Secret = blake3::Hash;

/// Hash for blocks in public chain
pub fn hash(input: &[u8]) -> Hash {
    blake3::hash(input)
}

pub fn keyed_hash(key: &[u8; 32], input: &[u8]) -> Hash {
    blake3::keyed_hash(key, input)
}

/// Hash for blocks in secret chain
pub fn hash_sec(input: &[u8]) -> SecHash {
    blake3::hash(input)
}

/// Derive a domain specific [Secret] from a context string and a root secret.
///
/// When doing hybrid signing, it is critical to derive a unique secret for each algorithm (say,
/// one for ed25519 and another for ML-DSA).
///
/// And even if signing with a single algorithm, we still should use a derived secret instead of the
/// root secret directly.
pub(crate) fn derive_secret(context: &str, secret: &Secret) -> Secret {
    if context.len() != 64 {
        panic!(
            "derive_secret(): context string length must be 64; got {}",
            context.len()
        );
    }
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(secret.as_bytes());
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::always::*;
    use crate::generate_secret;
    use std::collections::HashSet;

    #[test]
    fn test_generate_secret() {
        let count = 1024;
        let mut hset = HashSet::new();
        for _ in 0..count {
            assert!(hset.insert(generate_secret().unwrap()));
        }
        assert_eq!(hset.len(), count);
    }

    #[test]
    fn test_derive_secret() {
        let secret = Hash::from_bytes([7; 32]);

        let h = derive_secret(CONTEXT_SECRET, &secret);
        assert_eq!(
            h.as_bytes(),
            &[
                120, 255, 86, 223, 30, 100, 162, 199, 106, 136, 172, 87, 236, 29, 37, 87, 54, 34,
                187, 11, 86, 136, 243, 38, 218, 235, 136, 210, 10, 49, 145, 205
            ]
        );

        let h = derive_secret(CONTEXT_SECRET_NEXT, &secret);
        assert_eq!(
            h.as_bytes(),
            &[
                56, 77, 119, 202, 143, 168, 34, 136, 205, 197, 90, 11, 162, 112, 64, 45, 180, 80,
                53, 21, 110, 79, 164, 134, 252, 40, 223, 195, 105, 145, 116, 30
            ]
        );

        let secret = Hash::from_bytes([8; 32]);

        let h = derive_secret(CONTEXT_SECRET, &secret);
        assert_eq!(
            h.as_bytes(),
            &[
                204, 111, 146, 79, 175, 44, 54, 156, 189, 251, 132, 13, 239, 136, 191, 186, 33,
                207, 252, 183, 28, 52, 122, 92, 77, 16, 181, 179, 130, 180, 83, 141
            ]
        );

        let h = derive_secret(CONTEXT_SECRET_NEXT, &secret);
        assert_eq!(
            h.as_bytes(),
            &[
                21, 128, 0, 241, 82, 225, 6, 165, 5, 12, 101, 182, 221, 147, 193, 220, 120, 250,
                138, 223, 152, 199, 78, 68, 69, 51, 238, 203, 135, 83, 186, 246
            ]
        );
    }

    #[test]
    #[should_panic(expected = "derive_secret(): context string length must be 64; got 63")]
    fn test_derive_secret_panic_low() {
        let secret = generate_secret().unwrap();
        derive_secret(&CONTEXT_SECRET[0..63], &secret);
    }

    #[test]
    #[should_panic(expected = "derive_secret(): context string length must be 64; got 65")]
    fn test_derive_secret_panic_high() {
        let secret = generate_secret().unwrap();
        let mut context = String::from(CONTEXT_SECRET);
        context.push('7');
        derive_secret(&context, &secret);
    }
}
