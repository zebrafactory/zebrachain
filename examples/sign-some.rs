//! Create a new chain and some signatures.

use tempfile;
use zf_zebrachain::{Cursor, OwnedChainStore, PAYLOAD, Payload, Secret};

const COUNT: usize = 420;

fn build_payloads() -> Vec<Payload> {
    let mut payloads = Vec::with_capacity(COUNT);
    let mut buf = [0; PAYLOAD];
    for _ in 0..COUNT {
        getrandom::fill(&mut buf).unwrap();
        payloads.push(Payload::from_buf(&buf));
    }
    payloads
}

fn main() {
    println!("Pre-generating {} random signing requests...", COUNT);
    let payloads = build_payloads();
    let tmpdir = tempfile::TempDir::new().unwrap();
    let ocs = OwnedChainStore::new(tmpdir.path(), tmpdir.path());

    let password = Secret::generate().unwrap();
    let mut chain = ocs
        .generate_chain(&payloads[0], password.as_bytes())
        .unwrap();

    println!("Created new chain in directory {:?}", tmpdir.path());

    println!("Signing remaining {} requests... ", COUNT - 1);
    for payload in &payloads[1..] {
        chain.sign(&payload).unwrap();
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
    let secchain = ocs
        .secret_store()
        .open_chain(&chain_hash, password.as_bytes())
        .unwrap();

    println!("Iterating through secret chain and fully validating...");
    for result in &secchain {
        let _secblock = result.unwrap();
    }

    println!("Rebuilding public chain from secret chain...");
    let chain = ocs.secret_to_public(&secchain).unwrap();
    assert_eq!(&head, chain.head());
    assert_eq!(&tail, chain.tail());

    println!("Opening chain and fully validating...");
    let chain = ocs.open_chain(&chain_hash, password.as_bytes()).unwrap();
    println!("Head: {}", chain.head().block_hash);
    println!("Tead: {}", chain.tail().block_hash);
    println!("Count: {}", chain.count());
    assert_eq!(chain.count(), payloads.len() as u64);
    assert_eq!(&head, chain.head());
    assert_eq!(&tail, chain.tail());

    let checkpoint = tail.to_checkpoint();
    println!("Resuming chain from a checkpoint and partially validating...");
    let chain = ocs.resume_chain(&checkpoint, password.as_bytes()).unwrap();
    println!("Head: {}", chain.head().block_hash);
    println!("Tead: {}", chain.tail().block_hash);
    println!("Count: {}", chain.count());
    assert_eq!(chain.count(), payloads.len() as u64);
    assert_eq!(&head, chain.head());
    assert_eq!(&tail, chain.tail());

    println!("Stepping backward through chain using a Cursor...");
    let mut chain = chain.into_chain();
    let mut cursor = Cursor::from_tail(&mut chain);
    assert_eq!(&tail, cursor.block_state());
    while cursor.previous_block().unwrap() {
        assert_eq!(
            cursor.block_state().payload,
            payloads[cursor.block_state().block_index as usize]
        );
    }
    assert_eq!(&head, cursor.block_state());
}
