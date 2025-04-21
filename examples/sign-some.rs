//! Create a new chain and some signatures.

use tempfile;
use zf_zebrachain::{CheckPoint, OwnedChainStore, Payload, generate_secret};

const COUNT: usize = 420;

fn build_payloads() -> Vec<Payload> {
    let mut payloads = Vec::with_capacity(COUNT);
    for _ in 0..COUNT {
        payloads.push(Payload::new(0, generate_secret().unwrap()));
    }
    payloads
}

fn main() {
    println!("Pre-generating {} random signing requests...", COUNT);
    let payloads = build_payloads();
    let tmpdir = tempfile::TempDir::new().unwrap();
    let root_secret = generate_secret().unwrap();
    let ocs = OwnedChainStore::build(tmpdir.path(), tmpdir.path(), root_secret);
    let initial_entropy = generate_secret().unwrap();
    let mut chain = ocs.create_chain(&initial_entropy, &payloads[0]).unwrap();

    println!("Created new chain in directory {:?}", tmpdir.path());

    println!("Signing remaning {} requests... ", COUNT - 1);
    for payload in &payloads[1..] {
        let new_entropy = generate_secret().unwrap();
        chain.sign(&new_entropy, &payload).unwrap();
    }
    let chain_hash = chain.tail().chain_hash;
    let head = chain.head().clone();
    let tail = chain.tail().clone();
    println!("Head: {}", head.block_hash);
    println!("Tead: {}", tail.block_hash);
    println!("Count: {}", chain.count());

    println!("Opening chain and fully validating...");
    let chain = ocs.store().open_chain(&chain_hash).unwrap();
    println!("Iterating through chain and fully validating...");
    for result in &chain {
        let _state = result.unwrap();
        //println!("{}", state.block_hash);
    }
    println!("Removing public chain file...");
    ocs.store().remove_chain_file(&chain_hash).unwrap();

    println!("Opening secret chain and fully validating...");
    let secchain = ocs.secret_store().open_chain(&chain_hash).unwrap();

    println!("Iterating through secret chain and fully validating...");
    for result in &secchain {
        let _secblock = result.unwrap();
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
    assert_eq!(chain.count(), payloads.len() as u64);
    assert_eq!(&head, chain.head());
    assert_eq!(&tail, chain.tail());

    let checkpoint = CheckPoint::from_block_state(&tail);
    println!("Resuming chain from a checkpoint and partially validating...");
    let chain = ocs.resume_chain(&checkpoint).unwrap();
    println!("Head: {}", chain.head().block_hash);
    println!("Tead: {}", chain.tail().block_hash);
    println!("Count: {}", chain.count());
    assert_eq!(chain.count(), payloads.len() as u64);
    assert_eq!(&head, chain.head());
    assert_eq!(&tail, chain.tail());
}
