//! Create a new chain and some signatures.

use blake3::Hash;
use std::fs;
use tempfile;
use zebrachain::chain::Chain;
use zebrachain::fsutil::{build_filename, open_for_append};
use zebrachain::ownedchain::OwnedChainStore;
use zebrachain::secretchain::SecretChain;
use zebrachain::secretseed::random_hash;

fn build_state_hashes() -> Vec<Hash> {
    let count = 10_000;
    let mut states = Vec::with_capacity(count);
    for _ in 0..count {
        states.push(random_hash());
    }
    states
}

fn main() {
    let states = build_state_hashes();
    let tmpdir1 = tempfile::TempDir::new().unwrap();
    let tmpdir2 = tempfile::TempDir::new().unwrap();
    let ocs = OwnedChainStore::new(tmpdir1.path(), Some(tmpdir2.path()));
    let mut chain = ocs.create_owned_chain(&states[0]).unwrap();

    println!(
        "{} {} {}",
        chain.tail().chain_hash,
        chain.tail().block_hash,
        &states[0]
    );

    for state_hash in &states[1..] {
        chain.sign_next(&state_hash).unwrap();
        println!(
            "{} {} {}",
            chain.tail().chain_hash,
            chain.tail().block_hash,
            state_hash
        );
    }

    let chain_hash = chain.tail().chain_hash;
    let filename = build_filename(tmpdir1.path(), &chain_hash);
    println!("{:?}", filename);
    let file = open_for_append(&filename).unwrap();
    let chain = Chain::open(file, &chain_hash).unwrap();
    for result in &chain {
        let state = result.unwrap();
        println!("{}", state.block_hash);
    }
    fs::remove_file(&filename);

    let filename = build_filename(tmpdir2.path(), &chain_hash);
    let file = open_for_append(&filename).unwrap();
    let secchain = SecretChain::open(file).unwrap();

    for result in &secchain {
        let secblock = result.unwrap();
        println!("state_hash: {}", secblock.state_hash);
    }

    let chain = ocs.secret_to_public(&secchain).unwrap();
}
