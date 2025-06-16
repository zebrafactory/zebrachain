use hex_literal::hex;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use tempfile;
use zf_zebrachain::{
    BLOCK, ChainStore, DIGEST, Hash, MutSecretBlock, OwnedChainStore, PAYLOAD, Payload, SECRET,
    SECRET_BLOCK_AEAD, SECRET_CHAIN_HEADER, Secret, SecretChainHeader, SecretChainStore, Seed,
};

const SAMPLE_PAYLOAD_0: &str =
    "f78f0a75bd49cee04ae73541752b0122de2810fc1bf82d82da8950612769e877ca092af9e57a4662";
const SAMPLE_PAYLOAD_419: &str =
    "8ab3f4b28ab258bac7e42b43fd09c53e71b8aaebef302aa1db5fe12ec60b876980eda6a39d3afc94";

const BLOCK_HASH_0: &str =
    "f3b27d9068de4fbfe588871b83fa049ec40f2aa212251116dbdb1ec85b87f8c5b11f288bd902d19d";
const BLOCK_HASH_419: &str =
    "b284b9e26786b50d102fefaef4062af22752f8d99640c3fa04b1883c46dbeb13d589daa2f5aaf5a5";

const SECRET_BLOCK_HASH_0: &str =
    "6efa1dc28d8a64779e306e3b6f5566876dbf1b64db8b54eca5bdeec7e4924135246921c6f2e9c1f6";
const SECRET_BLOCK_HASH_419: &str =
    "cc5b881efbcb241386830d1fc07921660732e0bd84b089e04329fbdca6de56c22ae6c576f08b5fe3";

const FULL_CHAIN_HASH: &str =
    "3addcb096a3ddf4c5df61dfba5eca3a39f04c6975f699d8d11bc33404dc60993465c5da789f3beb4";
const FULL_SECRET_CHAIN_HASH: &str =
    "f5f74bac662854def4e51af8f3dea873d431ff1aa7f149a0188c7f35b15a4c1ba4c07c49710873b2";

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
static PASSWORD: &[u8] = b"Don't Ever Use This Password In Real Life";

fn sample_entropy(index: u64) -> Secret {
    let root = Secret::from_bytes(JUNK_ENTROPY);
    root.keyed_hash(&index.to_le_bytes())
}

#[test]
fn test_sample_entropy() {
    assert_eq!(
        sample_entropy(0).as_bytes(),
        &[
            242, 230, 239, 76, 178, 51, 51, 169, 87, 15, 73, 64, 38, 241, 26, 37, 204, 187, 207,
            249, 4, 196, 44, 186, 50, 165, 95, 62, 88, 57, 200, 155, 202, 33, 250, 72, 166, 147,
            66, 210, 176, 173, 198, 176, 200, 83, 234, 207
        ]
    );
    assert_eq!(
        sample_entropy(419).as_bytes(),
        &[
            12, 116, 50, 12, 242, 193, 80, 198, 167, 63, 5, 3, 139, 182, 139, 119, 118, 171, 186,
            155, 103, 210, 89, 216, 32, 93, 18, 5, 2, 51, 59, 70, 18, 112, 98, 227, 132, 69, 20,
            142, 7, 14, 38, 30, 189, 252, 209, 21
        ]
    );
    let mut hset: HashSet<Secret> = HashSet::with_capacity(420);
    for index in 0..420 {
        assert!(hset.insert(sample_entropy(index)));
    }
    assert_eq!(hset.len(), 420);
}

fn sample_storage_secret(index: u64) -> Secret {
    let root = Secret::from_bytes(JUNK_STORAGE_SECRET);
    root.keyed_hash(&index.to_le_bytes())
}

#[test]
fn test_sample_storage_secret() {
    assert_eq!(
        sample_storage_secret(0).as_bytes(),
        &[
            184, 239, 26, 147, 24, 96, 207, 58, 2, 131, 138, 253, 14, 9, 2, 9, 21, 62, 19, 202,
            146, 201, 148, 239, 201, 127, 238, 63, 143, 105, 180, 36, 39, 18, 72, 102, 117, 178,
            238, 53, 54, 41, 150, 241, 3, 210, 248, 96
        ]
    );
    assert_eq!(
        sample_storage_secret(419).as_bytes(),
        &[
            41, 27, 137, 191, 34, 61, 217, 246, 252, 231, 34, 120, 56, 43, 42, 149, 101, 105, 180,
            251, 219, 236, 37, 127, 57, 36, 30, 217, 4, 137, 210, 104, 248, 118, 122, 53, 24, 243,
            193, 203, 9, 125, 57, 204, 89, 57, 183, 51
        ]
    );
    let mut hset: HashSet<Secret> = HashSet::with_capacity(420);
    for index in 0..420 {
        assert!(hset.insert(sample_storage_secret(index)));
    }
    assert_eq!(hset.len(), 420);
}

fn sample_payload(index: u64) -> Payload {
    let root1 = Secret::from_bytes(JUNK_PAYLOAD_HASH).keyed_hash(&index.to_le_bytes());
    let state_hash = Hash::compute(root1.as_bytes());
    let root2 = Secret::from_bytes(JUNK_PAYLOAD_TIME).keyed_hash(&index.to_le_bytes());
    let time = u64::from_le_bytes(root2.as_bytes()[0..8].try_into().unwrap());
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
    let pw = Secret::generate().unwrap();
    let store = SecretChainStore::new(tmpdir.path());
    let chain_hash = Hash::from_bytes([42; DIGEST]);
    assert!(store.open_chain(&chain_hash, pw.as_bytes()).is_err());

    let mut buf = Vec::new();
    let payload = sample_payload(0);
    let mut block = MutSecretBlock::new(&mut buf, &payload);
    let seed = Seed::create(&sample_entropy(0));
    block.set_seed(&seed);
    block.set_public_block_hash(&chain_hash);

    let salt = Secret::generate().unwrap();
    let header = SecretChainHeader::create(salt);
    let chain_secret = header.derive_chain_secret(&chain_hash, pw.as_bytes());
    let block_hash = block.finalize(&chain_secret);
    let chain = store
        .create_chain(buf, header, chain_secret, &chain_hash, &block_hash)
        .unwrap();
    assert_eq!(chain.tail().payload, payload);
    let tail = chain.tail().clone();

    let chain = store.open_chain(&chain_hash, pw.as_bytes()).unwrap();
    assert_eq!(chain.tail(), &tail);
    store.remove_chain_file(&chain_hash).unwrap();
    assert!(store.open_chain(&chain_hash, pw.as_bytes()).is_err());
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
    let store = OwnedChainStore::build(tmpdir.path(), tmpdir.path());
    let mut chain = store
        .create_chain(&sample_entropy(0), &sample_payload(0), PASSWORD)
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
            .sign_raw(&sample_entropy(index), &sample_payload(index))
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

    // Hash the entire chain file to make extra sure we are consistent
    let chain_filename = tmpdir.path().join(format!("{}", chain.chain_hash()));
    let mut chain_file = File::open(&chain_filename).unwrap();
    let mut buf = Vec::new();
    chain_file.read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), BLOCK * 420);
    assert_eq!(
        Hash::compute(&buf),
        Hash::from_hex(FULL_CHAIN_HASH).unwrap()
    );

    // And hash the entire secret chain file too. This is extra important because this is how we
    // check that the secret block encryption is being done the same.
    let chain_filename = tmpdir.path().join(format!("{}.secret", chain.chain_hash()));
    let mut chain_file = File::open(&chain_filename).unwrap();
    let mut buf = Vec::new();
    chain_file.read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), SECRET_CHAIN_HEADER + SECRET_BLOCK_AEAD * 420);
    assert_eq!(
        Hash::compute(&buf),
        Hash::from_hex(FULL_SECRET_CHAIN_HASH).unwrap()
    );
}
