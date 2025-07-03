use hex_literal::hex;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use tempfile;
use zf_zebrachain::{
    BLOCK, ChainStore, DIGEST, Hash, MutSecretBlock, OwnedChainStore, PAYLOAD, Payload, SECRET,
    SECRET_BLOCK_AEAD, SECRET_CHAIN_HEADER, Secret, SecretChainHeader, SecretChainStore, Seed,
};

const SAMPLE_PAYLOAD_0: &[u8] =
    b"IYXUY8QNPV6NB6S8OPOEDHDFH48PEAU4GFZOMCVCSJYN4U6Y65RCBZRNJHS6DDQYHN95FBXQ";
const SAMPLE_PAYLOAD_419: &[u8] =
    b"ZV6CDGRNJXIDOZJPKWQ7H5XNJ674LPSVR9X7JNH7BLWSOWUDZJTC6QGLBJGYRHMQPRTMBLXS";

const BLOCK_HASH_0: &[u8] =
    b"AVL6IVH9RBVQ7ROBEZS8T94YFMVBX5LF5HUNE6ECB6Q8E6AJZUCAHPNKGHRD9JNVL8JDHTQ9";
const BLOCK_HASH_419: &[u8] =
    b"5RR9YI6UMTSGQAKBVEGPPSDYAAWSXSQ6YZWWQULRJIFPHAOUXM564NGXIRV9HLVPYHUM8L8G";

const SECRET_BLOCK_HASH_0: &[u8] =
    b"JOBGLDU4W8FXYVINAO6ALZUTGXGICSP498JQ4AH6XTU8Y6EESOHEOQO8Y8WNOES6T9ASGW9Q";
const SECRET_BLOCK_HASH_419: &[u8] =
    b"TPGOAJTE9IGIWTOXKW6WLDPLLUHRFDO9CW8MVS45QV4GXJEMC76D75CRUAFWMYPOPKSI5UJC";

const FULL_CHAIN_HASH: &[u8] =
    b"RNKGOUIQZ5GRQDAT9WC94WPMOEOKRROVX9FLA5GGNMR9SYJXGZTC7GKSDWSVBUHWZWUPPQDY";
const FULL_SECRET_CHAIN_HASH: &[u8] =
    b"RNWK6YFD5QD5TFHJ4H9UE6GQFJ9ZTMJSG7JZN6TPYZGNLDCC9KYO4HEG5G776M7FAYLWLHRN";

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
        Hash::from_z32(SAMPLE_PAYLOAD_0).unwrap()
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
        Hash::from_z32(SAMPLE_PAYLOAD_419).unwrap()
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
    let store = OwnedChainStore::new(tmpdir.path(), tmpdir.path());
    let mut chain = store
        .create_chain(&sample_entropy(0), &sample_payload(0), PASSWORD)
        .unwrap();
    assert_eq!(
        chain.head().block_hash,
        Hash::from_z32(BLOCK_HASH_0).unwrap()
    );
    assert_eq!(chain.head(), chain.tail());
    assert_eq!(
        chain.secret_tail().block_hash,
        Hash::from_z32(SECRET_BLOCK_HASH_0).unwrap()
    );
    for index in 1..420 {
        chain
            .sign_raw(&sample_entropy(index), &sample_payload(index))
            .unwrap();
    }
    assert_eq!(
        chain.head().block_hash,
        Hash::from_z32(BLOCK_HASH_0).unwrap()
    );
    assert_eq!(
        chain.tail().block_hash,
        Hash::from_z32(BLOCK_HASH_419).unwrap()
    );
    assert_eq!(
        chain.secret_tail().block_hash,
        Hash::from_z32(SECRET_BLOCK_HASH_419).unwrap()
    );
    assert_ne!(chain.head(), chain.tail());

    // Hash the entire chain file to make extra sure we are consistent.
    let chain_filename = tmpdir.path().join(format!("{}", chain.chain_hash()));
    let mut chain_file = File::open(&chain_filename).unwrap();
    let mut buf = Vec::new();
    chain_file.read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), BLOCK * 420);
    assert_eq!(
        Hash::compute(&buf),
        Hash::from_z32(FULL_CHAIN_HASH).unwrap()
    );

    // And hash the entire secret chain file too. This is important because this is how we check
    // that the secret block encryption is being done the same.
    let chain_filename = tmpdir.path().join(format!("{}.secret", chain.chain_hash()));
    let mut chain_file = File::open(&chain_filename).unwrap();
    let mut buf = Vec::new();
    chain_file.read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), SECRET_CHAIN_HEADER + SECRET_BLOCK_AEAD * 420);
    assert_eq!(
        Hash::compute(&buf),
        Hash::from_z32(FULL_SECRET_CHAIN_HASH).unwrap()
    );
}
