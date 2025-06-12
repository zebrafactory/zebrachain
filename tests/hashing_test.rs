use std::collections::HashSet;
use zf_zebrachain::{CONTEXT, DIGEST, Hash, HexError, SECRET, Secret, SubSecret192, SubSecret256};

#[test]
fn test_hash_compute() {
    let hash = Hash::compute(b"Just Rusting away");
    assert_eq!(
        hash.as_bytes(),
        &[
            231, 218, 170, 217, 143, 97, 208, 49, 238, 133, 89, 228, 237, 21, 55, 36, 216, 62, 107,
            78, 216, 194, 94, 24, 137, 227, 28, 31, 82, 69, 5, 134, 130, 196, 88, 140, 167, 118,
            110, 37
        ]
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
fn test_hash_from_hex() {
    let hash = Hash::from_hex(
        "26cd158316889c1435f38bf280fad89fb56284af132f62f817c71c10edb00aae3a853652ac33250e",
    )
    .unwrap();
    assert_eq!(
        hash,
        Hash::from_bytes([
            38, 205, 21, 131, 22, 136, 156, 20, 53, 243, 139, 242, 128, 250, 216, 159, 181, 98,
            132, 175, 19, 47, 98, 248, 23, 199, 28, 16, 237, 176, 10, 174, 58, 133, 54, 82, 172,
            51, 37, 14
        ])
    );
    assert_eq!(
        Hash::from_hex(
            "26cd158316889c1435f38bf280fad89fb56284af132f62f817c71c10edb00aae3a853652ac33250ee",
        ),
        Err(HexError::BadLen(81))
    );
    assert_eq!(
        Hash::from_hex(
            "26cd158316889c1435f38bf280fad89fb56284af132f62f817c71c10edb00aae3a853652ac33250",
        ),
        Err(HexError::BadLen(79))
    );
    assert_eq!(
        Hash::from_hex(
            "26cd158316889c1435f38bf280fad89fb56284af132f62f817c71c10edb00aae3a853652ac33250g",
        ),
        Err(HexError::BadByte(b"g"[0]))
    );
    assert_eq!(
        Hash::from_hex(
            "26cd158316889c1435f38bf280fad89fb56284af132f62f817c71c10edb00aae3a853652ac33250E",
        ),
        Err(HexError::BadByte(b"E"[0]))
    );
}

#[test]
fn test_hash_to_hex() {
    let hash = Hash::from_bytes([
        38, 205, 21, 131, 22, 136, 156, 20, 53, 243, 139, 242, 128, 250, 216, 159, 181, 98, 132,
        175, 19, 47, 98, 248, 23, 199, 28, 16, 237, 176, 10, 174, 58, 133, 54, 82, 172, 51, 37, 14,
    ]);
    assert_eq!(
        hash.to_hex().as_str(),
        "26cd158316889c1435f38bf280fad89fb56284af132f62f817c71c10edb00aae3a853652ac33250e"
    );
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
