use getrandom;
use std::collections::HashSet;
use zf_zebrachain::{SECRET, Secret, SecretBlockError, Seed};

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
fn test_seed_create() {
    let mut hset = HashSet::new();
    for _ in 0..420 {
        let initial_entropy = Secret::generate().unwrap();
        assert!(hset.insert(initial_entropy));
        let seed = Seed::create(&initial_entropy);
        assert!(hset.insert(seed.secret));
        assert!(hset.insert(seed.next_secret));
    }
    assert_eq!(hset.len(), 1260);
}

#[test]
fn test_seed_generate() {
    let mut hset = HashSet::new();
    for _ in 0..420 {
        let seed = Seed::generate().unwrap();
        assert!(hset.insert(seed.secret));
        assert!(hset.insert(seed.next_secret));
    }
    assert_eq!(hset.len(), 840);
}

#[test]
fn test_seed_next() {
    let mut hset = HashSet::new();
    let seed = Seed::generate().unwrap();
    assert!(hset.insert(seed.secret));
    assert!(hset.insert(seed.next_secret));
    for _ in 0..420 {
        let new_entropy = Secret::generate().unwrap();
        assert!(hset.insert(new_entropy));
        let seed2 = seed.next(&new_entropy);
        assert!(!hset.insert(seed2.secret));
        assert!(hset.insert(seed2.next_secret));
    }
    assert_eq!(hset.len(), 842);
}

#[test]
fn test_seed_advance() {
    let mut hset = HashSet::new();
    let seed = Seed::generate().unwrap();
    assert!(hset.insert(seed.secret));
    assert!(hset.insert(seed.next_secret));
    for _ in 0..420 {
        let seed2 = seed.advance().unwrap();
        assert!(!hset.insert(seed2.secret));
        assert!(hset.insert(seed2.next_secret));
    }
    assert_eq!(hset.len(), 422);
}

#[test]
fn test_seed_from_buf() {
    let mut buf = [0; SECRET * 2];
    getrandom::fill(&mut buf).unwrap();
    let seed = Seed::from_buf(&buf).unwrap();
    assert_eq!(&buf[0..SECRET], seed.secret.as_bytes());
    assert_eq!(&buf[SECRET..], seed.next_secret.as_bytes());

    // secret == next_secret
    buf[SECRET..].copy_from_slice(seed.secret.as_bytes());
    assert_eq!(Seed::from_buf(&buf), Err(SecretBlockError::Seed));

    // secret is zeros
    buf[0..SECRET].copy_from_slice(&[0; SECRET]);
    buf[SECRET..].copy_from_slice(seed.next_secret.as_bytes());
    assert_eq!(Seed::from_buf(&buf), Err(SecretBlockError::Seed));

    // next_secret is zeros
    buf[0..SECRET].copy_from_slice(seed.secret.as_bytes());
    buf[SECRET..].copy_from_slice(&[0; SECRET]);
    assert_eq!(Seed::from_buf(&buf), Err(SecretBlockError::Seed));
}

#[test]
fn test_seed_write_to_buf() {
    let seed = Seed::generate().unwrap();
    let mut buf = [0; SECRET * 2];
    seed.write_to_buf(&mut buf);
    assert_eq!(&buf[..SECRET], seed.secret.as_bytes());
    assert_eq!(&buf[SECRET..], seed.next_secret.as_bytes());
}
