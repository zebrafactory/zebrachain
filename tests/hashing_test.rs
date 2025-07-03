use std::collections::HashSet;
use zf_zebrachain::{CONTEXT, DIGEST, Hash, SECRET, Secret, SubSecret192, SubSecret256};

#[test]
fn test_hash_compute() {
    let hash = Hash::compute(b"Just Rusting away");
    assert_eq!(
        hash,
        Hash::from_z32(b"6MU6XRHVLX96SEZMW8NO9LOQ8PNLFRNJFQMY4A66BG7EPLI96CM4D55UKTOQLOAWGOJUX8LZ")
            .unwrap()
    );
}

#[test]
fn test_hash_from_slice() {
    let hash = Hash::from_slice(&[42; DIGEST]).unwrap();
    assert_eq!(hash.as_bytes(), &[42; DIGEST]);
    assert!(Hash::from_slice(&[42; DIGEST - 1]).is_err());
    assert!(Hash::from_slice(&[42; DIGEST + 1]).is_err());
}

#[test]
fn test_hash_from_bytes() {
    let hash = Hash::from_bytes([42; DIGEST]);
    assert_eq!(hash.as_bytes(), &[42; DIGEST]);
}

#[test]
fn test_hash_is_zeros() {
    let hash = Hash::from_bytes([0; DIGEST]);
    assert!(hash.is_zeros());
    let hash = Hash::from_bytes([69; DIGEST]);
    assert!(!hash.is_zeros());
}

#[test]
fn test_secret_generate() {
    let mut hset = HashSet::new();
    for _ in 0..420 {
        let secret = Secret::generate().unwrap();
        assert!(hset.insert(secret));
    }
    assert_eq!(hset.len(), 420);
}

#[test]
fn test_secret_from_slice() {
    let secret = Secret::from_slice(&[69; SECRET]).unwrap();
    assert_eq!(secret.as_bytes(), &[69; SECRET]);
    assert!(Secret::from_slice(&[69; SECRET - 1]).is_err());
    assert!(Secret::from_slice(&[69; SECRET + 1]).is_err());
}

#[test]
fn test_secret_from_bytes() {
    let secret = Secret::from_bytes([69; SECRET]);
    assert_eq!(secret.as_bytes(), &[69; SECRET]);
}

#[test]
fn test_secret_is_zeros() {
    let secret = Secret::from_bytes([0; SECRET]);
    assert!(secret.is_zeros());
    let secret = Secret::from_bytes([69; SECRET]);
    assert!(!secret.is_zeros());
}

#[test]
fn test_secret_mix() {
    let mut hset = HashSet::new();
    for _ in 0..69 {
        let secret = Secret::generate().unwrap();
        assert!(hset.insert(secret.clone()));
        for _ in 0..210 {
            let new_entropy = Secret::generate().unwrap();
            assert!(hset.insert(new_entropy.clone()));
            let next_secret = secret.mix(&new_entropy);
            assert!(hset.insert(next_secret));
        }
    }
    assert_eq!(hset.len(), 69 + 69 * 420);
}

#[test]
fn test_secret_mix_with_context() {
    let mut hset = HashSet::new();
    for _ in 0..69 {
        let secret = Secret::generate().unwrap();
        assert!(hset.insert(secret.clone()));
        for i in 0..=255 {
            let new_secret = secret.mix_with_context(&[i; CONTEXT]);
            assert!(hset.insert(new_secret));
        }
    }
    assert_eq!(hset.len(), 69 + 69 * 256);
}

#[test]
fn test_secret_mix_with_hash() {
    let mut hset = HashSet::new();
    for _ in 0..69 {
        let secret = Secret::generate().unwrap();
        assert!(hset.insert(secret.clone()));
        for i in 0..=255 {
            let hash = Hash::from_bytes([i; DIGEST]);
            let new_secret = secret.mix_with_hash(&hash);
            assert!(hset.insert(new_secret));
        }
    }
    assert_eq!(hset.len(), 69 + 69 * 256);
}

#[test]
fn test_secret_derive_sub_secret_256() {
    let mut hset: HashSet<SubSecret256> = HashSet::new();
    for _ in 0..42 {
        let secret = Secret::generate().unwrap();
        for block_index in 0..69 {
            for i in 0..=255 {
                let subsecret = secret.derive_sub_secret_256(block_index, &[i; CONTEXT]);
                assert!(hset.insert(subsecret));
            }
        }
    }
    assert_eq!(hset.len(), 42 * 69 * 256)
}

#[test]
fn test_secret_derive_sub_secret_192() {
    let mut hset: HashSet<SubSecret192> = HashSet::new();
    for _ in 0..42 {
        let secret = Secret::generate().unwrap();
        for block_index in 0..69 {
            for i in 0..=255 {
                let subsecret = secret.derive_sub_secret_192(block_index, &[i; CONTEXT]);
                assert!(hset.insert(subsecret));
            }
        }
    }
    assert_eq!(hset.len(), 42 * 69 * 256)
}
