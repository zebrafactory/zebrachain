use std::collections::HashSet;
use tempfile;
use zf_zebrachain::{
    ChainStore, DIGEST, Hash, MutSecretBlock, OwnedChainStore, PAYLOAD, Payload, Secret,
    SecretChainStore, Seed, hash, keyed_hash,
};

const SAMPLE_ENTROPY_0: &str = "96b3a086291fbcdef17e52e60731e96d8d36ae0944f2aad0c0c12a0c14e161ca";
const SAMPLE_ENTROPY_419: &str = "27068b40079a37f5ecfb01700135dc9a81d2c811878d2328475dd1724b40891a";

const SAMPLE_STORAGE_SECRET_0: &str =
    "28ad9dc97e10d576d16e3e94fe4ef944d3a3215b2aaec67398c70831515f964c";
const SAMPLE_STORAGE_SECRET_419: &str =
    "96c7864ce923cec5795c7a5316b961055ef762278e3c0ec9fa3a9a4c9729fd9c";

const SAMPLE_PAYLOAD_0: &str = "c0c76cbfd80b970d138cce4e466327b1f2ba96a7de9ecc2c98b8f4e7e462a8bc";
const SAMPLE_PAYLOAD_419: &str = "e9961e428776cb08e4c3c7c55d912716a1f9edca74da0adb8a7a7805bb536788";

const BLOCK_HASH_0: &str = "21826e128e0d2e790d02471e84f38a8717d3859c09ca32ad300b42686abb14c0";
const BLOCK_HASH_419: &str = "2c20f1a0e40886eefcb24622d7cd42469b4678487d703b8ed17dd7be54277525";

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
        Secret::from_hex(SAMPLE_ENTROPY_0).unwrap()
    );
    assert_eq!(
        sample_entropy(419),
        Secret::from_hex(SAMPLE_ENTROPY_419).unwrap()
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
        Secret::from_hex(SAMPLE_STORAGE_SECRET_0).unwrap()
    );
    assert_eq!(
        sample_storage_secret(419),
        Secret::from_hex(SAMPLE_STORAGE_SECRET_419).unwrap()
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
    let state_hash = hash(root.as_bytes());
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
