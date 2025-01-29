//! Create a new chain and some signatures.

use blake3::keyed_hash;
use tempfile;
use zebrachain::block::SigningRequest;
use zebrachain::chain::{Chain, ChainStore, CheckPoint};
use zebrachain::fsutil::{build_filename, open_for_append};
use zebrachain::ownedchain::OwnedChainStore;
use zebrachain::secretchain::{SecretChain, SecretChainStore};
use zebrachain::secretseed::random_secret;

fn build_requests() -> Vec<SigningRequest> {
    let count = 420;
    let mut requests = Vec::with_capacity(count);
    for _ in 0..count {
        requests.push(SigningRequest::new(
            random_secret().unwrap(),
            random_secret().unwrap(),
        ));
    }
    requests
}

fn main() {
    let requests = build_requests();
    let tmpdir1 = tempfile::TempDir::new().unwrap();
    let tmpdir2 = tempfile::TempDir::new().unwrap();
    let root_secret = random_secret().unwrap();
    let store = ChainStore::new(tmpdir1.path());
    let secstore = SecretChainStore::new(tmpdir2.path(), root_secret);
    let ocs = OwnedChainStore::new(store, secstore);
    let mut chain = ocs.create_chain(&requests[0]).unwrap();

    println!(
        "{} {} {}",
        chain.tail().chain_hash,
        chain.tail().block_hash,
        &requests[0].state_hash,
    );

    for request in &requests[1..] {
        chain.sign_next(&request).unwrap();
        println!(
            "{} {} {}",
            chain.tail().chain_hash,
            chain.tail().block_hash,
            request.state_hash
        );
    }

    let chain_hash = chain.tail().chain_hash;
    let head = chain.head().clone();
    let tail = chain.tail().clone();

    let filename = build_filename(tmpdir1.path(), &chain_hash);
    println!("{:?}", filename);
    let file = open_for_append(&filename).unwrap();
    let chain = Chain::open(file, &chain_hash).unwrap();
    for result in &chain {
        let state = result.unwrap();
        println!("{}", state.block_hash);
    }
    ocs.store().remove_chain_file(&chain_hash).unwrap();

    let chain_secret = keyed_hash(root_secret.as_bytes(), chain_hash.as_bytes());
    let filename = build_filename(tmpdir2.path(), &chain_hash);
    let file = open_for_append(&filename).unwrap();
    let secchain = SecretChain::open(file, chain_secret).unwrap();

    for result in &secchain {
        let secblock = result.unwrap();
        println!("state_hash: {}", secblock.state_hash);
    }

    let chain = ocs.secret_to_public(&secchain).unwrap();
    assert_eq!(&head, chain.head());
    assert_eq!(&tail, chain.tail());

    let chain = ocs.open_chain(&chain_hash).unwrap();
    println!("{} {}", chain.tail().index, chain.tail().block_hash);
    assert_eq!(chain.count(), requests.len() as u64);

    let checkpoint = CheckPoint::from_block_state(&tail);
    let chain = ocs.resume_chain(&checkpoint).unwrap();
    println!("{} {}", chain.tail().index, chain.tail().block_hash);
    assert_eq!(chain.count(), requests.len() as u64);
}
