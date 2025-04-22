use blake3::{Hash, Hasher, hash};
use std::collections::HashSet;
use tempfile;
use zf_zebrachain::{ChainStore, OwnedChainStore, PAYLOAD, Payload, generate_secret};

const SAMPLE_ENTROPY_0: &str = "eca6aab31954966c1996ef58a259aeeba4e2f8a20da25a22f254497a58cce2b0";
const SAMPLE_ENTROPY_419: &str = "f894663ee5f83bd79389c3a46ece561b84fc3ad079110f53b249d2df9f869e57";
const SAMPLE_STORAGE_SECRET_0: &str =
    "627aaf90e01f8d7901b5315f9b3f9bb8aae991c2ebc11e3a0adfecec3b780c47";
const SAMPLE_STORAGE_SECRET_419: &str =
    "52e76b9ee07681d252ea823416832deb2c8f3bf294cb6e0f5f770dc30a64faa3";
const SAMPLE_PAYLOAD_0: &str = "55f6dada8875897fc828d497d88187162f0530b56c9760810f01783b532c8fdd";
const SAMPLE_PAYLOAD_419: &str = "23c046161fceadefc410850888f4d8ffc006ce2759ac425919c8e08b75519c20";

const BLOCK_HASH_0: &str = "ce7151342243f72438037b2d2c32e43256523f2a87f8a0d54c9b3302c1c41a76";
const BLOCK_HASH_419: &str = "aa6ebc33cd4477b0420c698cb1c9e42e810e633f3296133c535e75a351522fe1";

fn sample_entropy(index: u64) -> Hash {
    let mut h = Hasher::new();
    h.update(
        b"This will be our bad entropy with random access. Do not do this in real life, haha.",
    );
    h.update(&index.to_le_bytes());
    h.finalize()
}

#[test]
fn test_sample_entropy() {
    assert_eq!(sample_entropy(0), Hash::from_hex(SAMPLE_ENTROPY_0).unwrap());
    assert_eq!(
        sample_entropy(419),
        Hash::from_hex(SAMPLE_ENTROPY_419).unwrap()
    );
    let mut hset: HashSet<Hash> = HashSet::with_capacity(420);
    for index in 0..420 {
        assert!(hset.insert(sample_entropy(index)));
    }
    assert_eq!(hset.len(), 420);
}

fn sample_storage_secret(index: u64) -> Hash {
    let mut h = Hasher::new();
    h.update(
        b"This will bad sample storage secret with random access. Seriously, do NOT do in real life.",
    );
    h.update(&index.to_le_bytes());
    h.finalize()
}

#[test]
fn test_sample_storage_secret() {
    assert_eq!(
        sample_storage_secret(0),
        Hash::from_hex(SAMPLE_STORAGE_SECRET_0).unwrap()
    );
    assert_eq!(
        sample_storage_secret(419),
        Hash::from_hex(SAMPLE_STORAGE_SECRET_419).unwrap()
    );
    let mut hset: HashSet<Hash> = HashSet::with_capacity(420);
    for index in 0..420 {
        assert!(hset.insert(sample_storage_secret(index)));
    }
    assert_eq!(hset.len(), 420);
}

fn sample_payload(index: u64) -> Payload {
    let mut h = Hasher::new();
    h.update(b"This will be our test payload generator with random access");
    h.update(&index.to_le_bytes());
    let root = h.finalize();
    let time = u64::from_le_bytes(root.as_bytes()[0..8].try_into().unwrap());
    let state_hash = hash(root.as_bytes());
    Payload::new(time, state_hash)
}

#[test]
fn test_chain_store() {
    let tmpdir = tempfile::TempDir::new().unwrap();
    let store = ChainStore::new(tmpdir.path());
    let chain_hash = generate_secret().unwrap();

    assert!(store.open_chain_file(&chain_hash).is_err());
    assert!(store.open_chain(&chain_hash).is_err());
}

#[test]
fn test_payload() {
    // index == 0
    let p = sample_payload(0);
    let mut buf = [0; PAYLOAD];
    p.write_to_buf(&mut buf);
    assert_eq!(hash(&buf), Hash::from_hex(SAMPLE_PAYLOAD_0).unwrap());
    let p2 = Payload::from_buf(&buf);
    assert_eq!(p, p2);
    let mut buf2 = [0; PAYLOAD];
    p2.write_to_buf(&mut buf2);
    assert_eq!(buf, buf2);

    // index == 419
    let p = sample_payload(419);
    let mut buf = [0; PAYLOAD];
    p.write_to_buf(&mut buf);
    assert_eq!(hash(&buf), Hash::from_hex(SAMPLE_PAYLOAD_419).unwrap());
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
        chain.sign(&sample_entropy(index), &sample_payload(index)).unwrap();
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
