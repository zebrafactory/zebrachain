use std::collections::HashSet;
use zf_zebrachain::{Seed, generate_secret};

#[test]
fn test_generate_secret() {
    let mut hset = HashSet::new();
    for _ in 0..420 {
        let secret = generate_secret().unwrap();
        assert!(hset.insert(secret));
    }
    assert_eq!(hset.len(), 420);
}

#[test]
fn test_seed_create() {
    let mut hset = HashSet::new();
    for _ in 0..420 {
        let initial_entropy = generate_secret().unwrap();
        assert!(hset.insert(initial_entropy));
        let seed = Seed::create(&initial_entropy);
        assert!(hset.insert(seed.secret));
        assert!(hset.insert(seed.next_secret));
    }
    assert_eq!(hset.len(), 1260);
}

#[test]
fn test_seed_auto_create() {
    let mut hset = HashSet::new();
    for _ in 0..420 {
        let seed = Seed::auto_create().unwrap();
        assert!(hset.insert(seed.secret));
        assert!(hset.insert(seed.next_secret));
    }
    assert_eq!(hset.len(), 840);
}

#[test]
fn test_seed_advance() {
    let mut hset = HashSet::new();
    let seed = Seed::auto_create().unwrap();
    assert!(hset.insert(seed.secret));
    assert!(hset.insert(seed.next_secret));
    for _ in 0..420 {
        let new_entropy = generate_secret().unwrap();
        assert!(hset.insert(new_entropy));
        let seed2 = seed.advance(&new_entropy);
        assert!(!hset.insert(seed2.secret));
        assert!(hset.insert(seed2.next_secret));
    }
    assert_eq!(hset.len(), 842);
}

#[test]
fn test_seed_auto_advance() {
    let mut hset = HashSet::new();
    let seed = Seed::auto_create().unwrap();
    assert!(hset.insert(seed.secret));
    assert!(hset.insert(seed.next_secret));
    for _ in 0..420 {
        let seed2 = seed.auto_advance().unwrap();
        assert!(!hset.insert(seed2.secret));
        assert!(hset.insert(seed2.next_secret));
    }
    assert_eq!(hset.len(), 422);
}
