//! Create a new chain and some signatures.

use blake3::keyed_hash;
use tempfile;
use zebrachain::block::SigningRequest;
use zebrachain::chain::{Chain, CheckPoint};
use zebrachain::fsutil::{chain_filename, open_for_append, secret_chain_filename};
use zebrachain::ownedchain::OwnedChainStore;
use zebrachain::secretchain::SecretChain;
use zebrachain::secretseed::random_secret;

const COUNT: usize = 42_000;

fn build_requests() -> Vec<SigningRequest> {
    let mut requests = Vec::with_capacity(COUNT);
    for _ in 0..COUNT {
        requests.push(SigningRequest::new(
            0,
            random_secret().unwrap(),
            random_secret().unwrap(),
        ));
    }
    requests
}

fn main() {
    let requests = build_requests();
    let tmpdir = tempfile::TempDir::new().unwrap();
    let root_secret = random_secret().unwrap();
    let ocs = OwnedChainStore::build(tmpdir.path(), tmpdir.path(), root_secret);
    let initial_entropy = random_secret().unwrap();
    let mut chain = ocs.create_chain(&initial_entropy, &requests[0]).unwrap();

    println!(
        "{} {} {}",
        chain.tail().chain_hash,
        chain.tail().block_hash,
        &requests[0].state_hash,
    );

    for request in &requests[1..] {
        let new_entropy = random_secret().unwrap();
        chain.sign(&new_entropy, &request).unwrap();
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

    let filename = chain_filename(tmpdir.path(), &chain_hash);
    println!("{:?}", filename);
    let file = open_for_append(&filename).unwrap();
    let chain = Chain::open(file, &chain_hash).unwrap();
    for result in &chain {
        let state = result.unwrap();
        println!("{}", state.block_hash);
    }
    ocs.store().remove_chain_file(&chain_hash).unwrap();

    let chain_secret = keyed_hash(root_secret.as_bytes(), chain_hash.as_bytes());
    let filename = secret_chain_filename(tmpdir.path(), &chain_hash);
    let file = open_for_append(&filename).unwrap();
    let secchain = SecretChain::open(file, chain_secret).unwrap();

    for result in &secchain {
        let secblock = result.unwrap();
        println!("state_hash: {}", secblock.request.state_hash);
    }

    let chain = ocs.secret_to_public(&secchain).unwrap();
    assert_eq!(&head, chain.head());
    assert_eq!(&tail, chain.tail());

    let chain = ocs.open_chain(&chain_hash).unwrap();
    println!("{} {}", chain.tail().index, chain.tail().block_hash);
    assert_eq!(chain.count(), requests.len() as u64);
    assert_eq!(&head, chain.head());
    assert_eq!(&tail, chain.tail());

    let checkpoint = CheckPoint::from_block_state(&tail);
    let chain = ocs.resume_chain(&checkpoint).unwrap();
    println!("{} {}", chain.tail().index, chain.tail().block_hash);
    assert_eq!(chain.count(), requests.len() as u64);
    assert_eq!(&head, chain.head());
    assert_eq!(&tail, chain.tail());
}
