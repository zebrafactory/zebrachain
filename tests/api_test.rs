use hex_literal::hex;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use tempfile;
use zf_zebrachain::{
    BLOCK, ChainStore, DIGEST, Hash, MutSecretBlock, OwnedChainStore, PAYLOAD, Payload, SECRET,
    Secret, SecretChainStore, Seed,
};

const SAMPLE_PAYLOAD_0: &str =
    "8e11460d9b318fa727025dd624f25ec398147cfd2b05a40f1298687a4047b9c29bfea7a32bbb58c2";
const SAMPLE_PAYLOAD_419: &str =
    "a0be8279752f518432298ee05b7938dcdd4e50dd4fb31ae99ec89ce24e188a4a7257c2842a963e7d";

const BLOCK_HASH_0: &str =
    "55475ddbcd1ce753723ee29acf66613be45deed35b1bfdcc761734f7b9c15529631bc8b283b8bc31";
const BLOCK_HASH_419: &str =
    "15bcb456a70da15bdb9ffee8d01f58b04048d1c274ceecd86641df30a405b536a097d8bf82c65f99";

const SECRET_BLOCK_HASH_0: &str =
    "bf1b0d15119ad14828188a83df106f51311b5af25b5507f4b7ca9c7d390cf749ebe73f107d5d3fa6";
const SECRET_BLOCK_HASH_419: &str =
    "618d36885c04a07fe1cbecba765b2b5bed9c8712ddb5831e7f9e55db78f7083b5090218012799538";

const FULL_CHAIN_HASH: &str =
    "eed62f2c674b247aed59f196fa92e9f7b7a0828e4f8c0dce31be192d74203d1a5b14349f61671e15";

static JUNK_ENTROPY: [u8; SECRET] = hex!(
    "517931cc2f0085cd414b57a07680df2c3097c9030be69f51990cee94b26dbe07a0ee06c69f4b1e0de776c3afc497f948"
);
static JUNK_STORAGE_SECRET: [u8; SECRET] = hex!(
    "fcf6001000386480f934d9f7bcf0bf661a11ffa58cd3346f33845bea2db3745e42213bb6f293d900de755dc6dace62a2"
);
static JUNK_PAYLOAD_HASH: [u8; SECRET] = hex!(
    "c3957f061243c2241e08f2f37df954770153d724fa37a644a1682a06bdcb546087ab57b5e7a35b077f2101bea8326ebe"
);
static JUNK_PAYLOAD_TIME: [u8; SECRET] = hex!(
    "245eec220526eff45ad9f14cc01c7d2d7002910d5c6b98e10faf926c12e2711eea908b0a9d50523fbd602fb456584d74"
);

fn sample_entropy(index: u128) -> Secret {
    let root = Secret::from_bytes(JUNK_ENTROPY);
    root.keyed_hash(&index.to_le_bytes())
}

#[test]
fn test_sample_entropy() {
    assert_eq!(
        sample_entropy(0).as_bytes(),
        &[
            188, 75, 162, 140, 243, 202, 214, 235, 249, 24, 62, 189, 239, 213, 48, 126, 30, 15, 20,
            5, 89, 188, 124, 180, 244, 186, 122, 114, 207, 215, 161, 190, 87, 44, 169, 192, 78,
            159, 177, 225, 192, 51, 50, 212, 57, 100, 67, 146
        ]
    );
    assert_eq!(
        sample_entropy(419).as_bytes(),
        &[
            102, 138, 91, 147, 7, 148, 195, 246, 107, 174, 47, 196, 35, 9, 1, 253, 15, 159, 153,
            55, 74, 47, 18, 49, 184, 132, 97, 253, 36, 112, 152, 38, 140, 97, 71, 244, 45, 222, 44,
            158, 220, 132, 170, 207, 148, 143, 115, 95
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
    root.keyed_hash(&index.to_le_bytes())
}

#[test]
fn test_sample_storage_secret() {
    assert_eq!(
        sample_storage_secret(0).as_bytes(),
        &[
            152, 170, 109, 216, 231, 164, 137, 210, 215, 218, 38, 245, 199, 75, 128, 173, 138, 20,
            92, 209, 17, 64, 169, 250, 212, 49, 154, 187, 20, 114, 62, 207, 113, 152, 210, 93, 51,
            115, 187, 174, 22, 14, 94, 77, 166, 92, 141, 190
        ]
    );
    assert_eq!(
        sample_storage_secret(419).as_bytes(),
        &[
            56, 130, 230, 202, 59, 239, 46, 177, 70, 112, 229, 226, 199, 119, 79, 169, 180, 76, 84,
            237, 99, 232, 227, 241, 216, 74, 214, 230, 191, 69, 172, 90, 12, 254, 63, 230, 154,
            189, 130, 204, 128, 204, 104, 76, 60, 189, 220, 42
        ]
    );
    let mut hset: HashSet<Secret> = HashSet::with_capacity(420);
    for index in 0..420 {
        assert!(hset.insert(sample_storage_secret(index)));
    }
    assert_eq!(hset.len(), 420);
}

fn sample_payload(index: u128) -> Payload {
    let root1 = Secret::from_bytes(JUNK_PAYLOAD_HASH).keyed_hash(&index.to_le_bytes());
    let state_hash = Hash::compute(root1.as_bytes());
    let root2 = Secret::from_bytes(JUNK_PAYLOAD_TIME).keyed_hash(&index.to_le_bytes());
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
    let store = SecretChainStore::new(tmpdir.path(), storage_secret.clone());
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
    assert_eq!(
        chain.secret_tail().block_hash,
        Hash::from_hex(SECRET_BLOCK_HASH_0).unwrap()
    );
    for index in 1..420 {
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
    assert_eq!(
        chain.secret_tail().block_hash,
        Hash::from_hex(SECRET_BLOCK_HASH_419).unwrap()
    );
    assert_ne!(chain.head(), chain.tail());

    // Hash entire chain file to make extra sure we are consistent
    let chain_filename = tmpdir.path().join(format!("{}", chain.chain_hash()));
    let mut chain_file = File::open(&chain_filename).unwrap();
    let mut buf = Vec::new();
    chain_file.read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), BLOCK * 420);
    assert_eq!(
        Hash::compute(&buf),
        Hash::from_hex(FULL_CHAIN_HASH).unwrap()
    );
}
