use hex_literal::hex;
use std::collections::HashSet;
use tempfile;
use zf_zebrachain::{
    ChainStore, DIGEST, Hash, MutSecretBlock, OwnedChainStore, PAYLOAD, Payload, Secret,
    SecretChainStore, Seed, keyed_hash,
};

const SAMPLE_PAYLOAD_0: &str = "d5b8c07e502ecfe37ae644d9bb91ba3f409fff5dbf3856e87a4ec09143f7789d";
const SAMPLE_PAYLOAD_419: &str = "dc54d0feef9a7986e306947a5e3c31540dea6c473705f79eaf39a6e9dac2c93b";

const BLOCK_HASH_0: &str = "097041ea3d9e06143a9dbde20406721dbe39314b87ee138208669f7f5be4710f";
const BLOCK_HASH_419: &str = "5e05321293c71fa73f38f43ddea64ddff8050f77dfd89f4eae3882b1e83aaf00";

fn sample_entropy(index: u128) -> Secret {
    let mut h = blake3::Hasher::new();
    h.update(
        b"This will be our bad entropy with random access. Do not do this in real life, haha.",
    );
    h.update(&index.to_le_bytes());
    Secret::from_bytes(*h.finalize().as_bytes())
}

#[test]
fn test_sample_entropy() {
    assert_eq!(
        sample_entropy(0),
        Secret::from_bytes(hex!(
            "96b3a086291fbcdef17e52e60731e96d8d36ae0944f2aad0c0c12a0c14e161ca"
        ))
    );
    assert_eq!(
        sample_entropy(419),
        Secret::from_bytes(hex!(
            "27068b40079a37f5ecfb01700135dc9a81d2c811878d2328475dd1724b40891a"
        ))
    );
    let mut hset: HashSet<Secret> = HashSet::with_capacity(420);
    for index in 0..420 {
        assert!(hset.insert(sample_entropy(index)));
    }
    assert_eq!(hset.len(), 420);
}

fn sample_storage_secret(index: u128) -> Secret {
    let mut h = blake3::Hasher::new();
    h.update(
        b"This will a bad sample storage secret with random access. Seriously, do NOT do in real life.",
    );
    h.update(&index.to_le_bytes());
    Secret::from_bytes(*h.finalize().as_bytes())
}

#[test]
fn test_sample_storage_secret() {
    assert_eq!(
        sample_storage_secret(0),
        Secret::from_bytes(hex!(
            "28ad9dc97e10d576d16e3e94fe4ef944d3a3215b2aaec67398c70831515f964c"
        ))
    );
    assert_eq!(
        sample_storage_secret(419),
        Secret::from_bytes(hex!(
            "96c7864ce923cec5795c7a5316b961055ef762278e3c0ec9fa3a9a4c9729fd9c"
        ))
    );
    let mut hset: HashSet<Secret> = HashSet::with_capacity(420);
    for index in 0..420 {
        assert!(hset.insert(sample_storage_secret(index)));
    }
    assert_eq!(hset.len(), 420);
}

fn sample_payload(index: u128) -> Payload {
    let mut h = blake3::Hasher::new();
    h.update(b"This will be our test payload generator with random access");
    h.update(&index.to_le_bytes());
    let root = h.finalize();
    let time = u128::from_le_bytes(root.as_bytes()[0..16].try_into().unwrap());
    let state_hash = Hash::compute(root.as_bytes());
    Payload::new(time, state_hash)
}

#[test]
fn test_chain_store() {
    let tmpdir = tempfile::TempDir::new().unwrap();
    let store = ChainStore::new(tmpdir.path());
    let chain_hash = Hash::from_bytes([42; DIGEST]);
    assert!(store.open_chain(&chain_hash).is_err());
    assert!(store.remove_chain_file(&chain_hash).is_err());
}

#[test]
fn test_secret_chain_store() {
    let tmpdir = tempfile::TempDir::new().unwrap();
    let storage_secret = Secret::generate().unwrap();
    let store = SecretChainStore::new(tmpdir.path(), storage_secret);
    let chain_hash = Hash::from_bytes([42; DIGEST]);
    assert!(store.open_chain(&chain_hash).is_err());

    let mut buf = Vec::new();
    let payload = sample_payload(0);
    let mut block = MutSecretBlock::new(&mut buf, &payload);
    let seed = Seed::create(&sample_entropy(0));
    block.set_seed(&seed);
    block.set_public_block_hash(&chain_hash);

    let chain_secret = Secret::from_bytes(
        *keyed_hash(storage_secret.as_bytes(), chain_hash.as_bytes()).as_bytes(),
    );
    let block_hash = block.finalize(&chain_secret);
    let chain = store.create_chain(&chain_hash, buf, &block_hash).unwrap();
    assert_eq!(chain.tail().payload, payload);
    let tail = chain.tail().clone();

    let chain = store.open_chain(&chain_hash).unwrap();
    assert_eq!(chain.tail(), &tail);
    store.remove_chain_file(&chain_hash).unwrap();
    assert!(store.open_chain(&chain_hash).is_err());
    assert!(store.remove_chain_file(&chain_hash).is_err());
}

#[test]
fn test_payload() {
    // index == 0
    let p = sample_payload(0);
    let mut buf = [0; PAYLOAD];
    p.write_to_buf(&mut buf);
    assert_eq!(
        Hash::compute(&buf),
        Hash::from_hex(SAMPLE_PAYLOAD_0).unwrap()
    );
    let p2 = Payload::from_buf(&buf);
    assert_eq!(p, p2);
    let mut buf2 = [0; PAYLOAD];
    p2.write_to_buf(&mut buf2);
    assert_eq!(buf, buf2);

    // index == 419
    let p = sample_payload(419);
    let mut buf = [0; PAYLOAD];
    p.write_to_buf(&mut buf);
    assert_eq!(
        Hash::compute(&buf),
        Hash::from_hex(SAMPLE_PAYLOAD_419).unwrap()
    );
    let p2 = Payload::from_buf(&buf);
    assert_eq!(p, p2);
    let mut buf2 = [0; PAYLOAD];
    p2.write_to_buf(&mut buf2);
    assert_eq!(buf, buf2);
}

#[test]
fn test_owned_chain_store() {
    let tmpdir = tempfile::TempDir::new().unwrap();
    let store = OwnedChainStore::build(tmpdir.path(), tmpdir.path(), sample_storage_secret(0));
    let mut chain = store
        .create_chain(&sample_entropy(0), &sample_payload(0))
        .unwrap();
    assert_eq!(
        chain.head().block_hash,
        Hash::from_hex(BLOCK_HASH_0).unwrap()
    );
    assert_eq!(chain.head(), chain.tail());
    for index in 0..420 {
        chain
            .sign(&sample_entropy(index), &sample_payload(index))
            .unwrap();
    }
    assert_eq!(
        chain.head().block_hash,
        Hash::from_hex(BLOCK_HASH_0).unwrap()
    );
    assert_eq!(
        chain.tail().block_hash,
        Hash::from_hex(BLOCK_HASH_419).unwrap()
    );
    assert_ne!(chain.head(), chain.tail());
}
