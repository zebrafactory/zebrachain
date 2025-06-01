use hex_literal::hex;
use std::collections::HashSet;
use tempfile;
use zf_zebrachain::{
    ChainStore, DIGEST, Hash, MutSecretBlock, OwnedChainStore, PAYLOAD, Payload, SECRET, Secret,
    SecretChainStore, Seed,
};

const SAMPLE_PAYLOAD_0: &str =
    "42cf453c90237ad093a8d7a8b202f681ee8d08d719e884922c5769a1c9b3f9eaba4313fcaa81c2c1";
const SAMPLE_PAYLOAD_419: &str =
    "31881c77273fdff74c274a172816a6c327bede16ab52c360fb0e6bbd3f16ede8dabc2ee7b776df6f";

const BLOCK_HASH_0: &str =
    "12335497a781ef465f846177d59fdf3e8cff4a5faf54b51a0bdf359521b5d126c41a6fc10f00debe";
const BLOCK_HASH_419: &str =
    "ecdaab59c79db94b82b953884d9fce0aa4cb9a451d4f5d6f96ee279f5cb0871bfc4104eae4fb4017";

static JUNK_ENTROPY: [u8; SECRET] =
    hex!("4e08e740cad03d0ac8ed4d2d1577b6f48bf6865c0e5c12eeb2082ea95cbda17b");
static JUNK_STORAGE_SECRET: [u8; SECRET] =
    hex!("8c793ba2e78be472b42e921dd0d318a5115c1e45c7f9bd2f71b61270cf39b4a4");
static JUNK_PAYLOAD_HASH: [u8; SECRET] =
    hex!("7f24701c4590693a7bb12a6353b87aa9c108721753c92cf24b49a65664c521bf");
static JUNK_PAYLOAD_TIME: [u8; SECRET] =
    hex!("c34790c3c9e52ab1b166280a5b4493177379c65eaf48f43da0e1d31b79775c82");

fn sample_entropy(index: u128) -> Secret {
    let root = Secret::from_bytes(JUNK_ENTROPY);
    root.derive_with_index(index)
}

#[test]
fn test_sample_entropy() {
    assert_eq!(
        sample_entropy(0).as_bytes(),
        &[
            2, 29, 36, 57, 58, 211, 249, 151, 248, 187, 183, 155, 253, 216, 35, 19, 176, 243, 124,
            54, 211, 94, 46, 161, 66, 252, 205, 199, 209, 12, 178, 158
        ]
    );
    assert_eq!(
        sample_entropy(419).as_bytes(),
        &[
            76, 13, 125, 88, 182, 80, 198, 81, 150, 37, 89, 228, 80, 199, 254, 210, 214, 45, 232,
            67, 75, 6, 29, 177, 2, 139, 225, 146, 137, 138, 3, 57
        ]
    );
    let mut hset: HashSet<Secret> = HashSet::with_capacity(420);
    for index in 0..420 {
        assert!(hset.insert(sample_entropy(index)));
    }
    assert_eq!(hset.len(), 420);
}

fn sample_storage_secret(index: u128) -> Secret {
    let root = Secret::from_bytes(JUNK_STORAGE_SECRET);
    root.derive_with_index(index)
}

#[test]
fn test_sample_storage_secret() {
    assert_eq!(
        sample_storage_secret(0).as_bytes(),
        &[
            104, 5, 141, 133, 209, 125, 24, 252, 124, 178, 41, 70, 11, 100, 202, 185, 110, 147,
            248, 151, 175, 21, 248, 214, 87, 195, 2, 109, 240, 97, 185, 226
        ]
    );
    assert_eq!(
        sample_storage_secret(419).as_bytes(),
        &[
            117, 99, 61, 219, 216, 54, 178, 20, 228, 47, 225, 8, 99, 71, 234, 59, 73, 52, 240, 213,
            251, 212, 249, 110, 77, 32, 85, 33, 115, 173, 149, 250
        ]
    );
    let mut hset: HashSet<Secret> = HashSet::with_capacity(420);
    for index in 0..420 {
        assert!(hset.insert(sample_storage_secret(index)));
    }
    assert_eq!(hset.len(), 420);
}

fn sample_payload(index: u128) -> Payload {
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
