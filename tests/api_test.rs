use hex_literal::hex;
use std::collections::HashSet;
use tempfile;
use zf_zebrachain::{
    ChainStore, DIGEST, Hash, MutSecretBlock, OwnedChainStore, PAYLOAD, Payload, SECRET, Secret,
    SecretChainStore, Seed,
};

const SAMPLE_PAYLOAD_0: &str =
    "eb5067a7054a1a98d2bb45ad374c41f8ce19a9d024215ad2c81d17a6381b5b884c5345f48472a5f2";
const SAMPLE_PAYLOAD_419: &str =
    "a10c124d75644122d7ac86c2af22b2b4de6592985a149a7a9cb88f0c976d61e802f1c7347a791677";

const BLOCK_HASH_0: &str =
    "4e72993e49db3ee522a387108af97c68e6dab90ff3a5d33a16b96ae19799c7074d327b4b63e3483f";
const BLOCK_HASH_419: &str =
    "331fe7b3e43ef36698d62b2dcea8068322629f624158c81b9ac995d68ebb02dce734b4826791f5a8";

static JUNK_ENTROPY: [u8; SECRET] =
    hex!("4e08e740cad03d0ac8ed4d2d1577b6f48bf6865c0e5c12eeb2082ea95cbda17b");
static JUNK_STORAGE_SECRET: [u8; SECRET] =
    hex!("8c793ba2e78be472b42e921dd0d318a5115c1e45c7f9bd2f71b61270cf39b4a4");
static JUNK_PAYLOAD_HASH: [u8; SECRET] =
    hex!("7f24701c4590693a7bb12a6353b87aa9c108721753c92cf24b49a65664c521bf");
static JUNK_PAYLOAD_TIME: [u8; SECRET] =
    hex!("c34790c3c9e52ab1b166280a5b4493177379c65eaf48f43da0e1d31b79775c82");

fn sample_entropy(index: u64) -> Secret {
    let root = Secret::from_bytes(JUNK_ENTROPY);
    root.derive_with_index(index)
}

#[test]
fn test_sample_entropy() {
    assert_eq!(
        sample_entropy(0),
        Secret::from_bytes([
            93, 99, 16, 92, 27, 103, 79, 94, 191, 105, 131, 9, 22, 202, 43, 105, 70, 139, 26, 203,
            223, 222, 82, 176, 124, 157, 172, 42, 113, 213, 0, 194
        ])
    );
    assert_eq!(
        sample_entropy(419),
        Secret::from_bytes([
            251, 254, 81, 169, 131, 113, 14, 45, 220, 27, 201, 193, 179, 94, 16, 233, 153, 65, 58,
            247, 71, 86, 33, 244, 249, 49, 247, 3, 51, 44, 46, 10
        ])
    );
    let mut hset: HashSet<Secret> = HashSet::with_capacity(420);
    for index in 0..420 {
        assert!(hset.insert(sample_entropy(index)));
    }
    assert_eq!(hset.len(), 420);
}

fn sample_storage_secret(index: u64) -> Secret {
    let root = Secret::from_bytes(JUNK_STORAGE_SECRET);
    root.derive_with_index(index)
}

#[test]
fn test_sample_storage_secret() {
    assert_eq!(
        sample_storage_secret(0),
        Secret::from_bytes([
            143, 62, 12, 13, 4, 93, 97, 188, 186, 30, 18, 30, 225, 39, 181, 176, 249, 7, 61, 147,
            106, 81, 117, 51, 176, 132, 21, 53, 63, 25, 37, 229
        ])
    );
    assert_eq!(
        sample_storage_secret(419),
        Secret::from_bytes([
            44, 207, 192, 131, 200, 167, 204, 128, 55, 125, 129, 149, 2, 195, 150, 27, 77, 65, 53,
            202, 33, 160, 94, 186, 68, 39, 96, 93, 53, 48, 39, 117
        ])
    );
    let mut hset: HashSet<Secret> = HashSet::with_capacity(420);
    for index in 0..420 {
        assert!(hset.insert(sample_storage_secret(index)));
    }
    assert_eq!(hset.len(), 420);
}

fn sample_payload(index: u64) -> Payload {
    let root1 = Secret::from_bytes(JUNK_PAYLOAD_HASH).derive_with_index(index);
    let state_hash = Hash::compute(root1.as_bytes());
    let root2 = Secret::from_bytes(JUNK_PAYLOAD_TIME).derive_with_index(index);
    let time = u128::from_le_bytes(root2.as_bytes()[0..16].try_into().unwrap());
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

    let chain_secret = storage_secret.derive_with_hash(&chain_hash);
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
