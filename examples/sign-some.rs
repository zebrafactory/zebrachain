//! Create a new chain and some signatures.

use blake3::keyed_hash;
use tempfile;
use zebrachain::block::SigningRequest;
use zebrachain::chain::{Chain, CheckPoint};
use zebrachain::fsutil::{chain_filename, open_for_append, secret_chain_filename};
use zebrachain::ownedchain::OwnedChainStore;
use zebrachain::secretchain::SecretChain;
use zebrachain::secretseed::generate_secret;

const COUNT: usize = 42_000;

fn build_requests() -> Vec<SigningRequest> {
    let mut requests = Vec::with_capacity(COUNT);
    for _ in 0..COUNT {
        requests.push(SigningRequest::new(
            0,
            generate_secret().unwrap(),
            generate_secret().unwrap(),
        ));
    }
    requests
}

fn main() {
    println!("Pre-generating {} random signing requests...", COUNT);
    let requests = build_requests();
    let tmpdir = tempfile::TempDir::new().unwrap();
    let root_secret = generate_secret().unwrap();
    let ocs = OwnedChainStore::build(tmpdir.path(), tmpdir.path(), root_secret);
    let initial_entropy = generate_secret().unwrap();
    let mut chain = ocs.create_chain2(&initial_entropy, &requests[0]).unwrap();

    println!("Created new chain in directory {:?}", tmpdir.path());

    println!("Signing remaning {} requests... ", COUNT - 1);
    for request in &requests[1..] {
        let new_entropy = generate_secret().unwrap();
        chain.sign(&new_entropy, &request).unwrap();
    }
    let chain_hash = chain.tail().chain_hash;
    let head = chain.head().clone();
    let tail = chain.tail().clone();
    println!("Head: {}", head.block_hash);
    println!("Tead: {}", tail.block_hash);
    println!("Count: {}", chain.count());

    let filename = chain_filename(tmpdir.path(), &chain_hash);
    let file = open_for_append(&filename).unwrap();
    println!("Opening chain and fully validating...");
    let chain = Chain::open(file, &chain_hash).unwrap();
    println!("Iterating through chain and fully validating...");
    for result in &chain {
        let _state = result.unwrap();
        //println!("{}", state.block_hash);
    }
    println!("Removing public chain file {:?}", filename);
    ocs.store().remove_chain_file(&chain_hash).unwrap();

    let chain_secret = keyed_hash(root_secret.as_bytes(), chain_hash.as_bytes());
    let filename = secret_chain_filename(tmpdir.path(), &chain_hash);
    let file = open_for_append(&filename).unwrap();
    println!("Opening secret chain and fully validating...");
    let secchain = SecretChain::open(file, chain_secret).unwrap();

    println!("Iterating through secret chain and fully validating...");
    for result in &secchain {
        let _secblock = result.unwrap();
        //println!("state_hash: {}", secblock.request.state_hash);
    }

    println!("Rebuilding public chain from secret chain...");
    let chain = ocs.secret_to_public(&secchain).unwrap();
    assert_eq!(&head, chain.head());
    assert_eq!(&tail, chain.tail());

    println!("Opening chain and fully validating...");
    let chain = ocs.open_chain(&chain_hash).unwrap();
    println!("Head: {}", chain.head().block_hash);
    println!("Tead: {}", chain.tail().block_hash);
    println!("Count: {}", chain.count());
    assert_eq!(chain.count(), requests.len() as u64);
    assert_eq!(&head, chain.head());
    assert_eq!(&tail, chain.tail());

    let checkpoint = CheckPoint::from_block_state(&tail);
    println!("Resuming chain from a checkpoint and partially validating...");
    let chain = ocs.resume_chain(&checkpoint).unwrap();
    println!("Head: {}", chain.head().block_hash);
    println!("Tead: {}", chain.tail().block_hash);
    println!("Count: {}", chain.count());
    assert_eq!(chain.count(), requests.len() as u64);
    assert_eq!(&head, chain.head());
    assert_eq!(&tail, chain.tail());
}
