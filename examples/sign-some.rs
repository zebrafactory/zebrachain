//! Create a new chain and some signatures.

use blake3::Hash;
use tempfile;
use zebrachain::ownedchain::SignerMajig;
use zebrachain::secretseed::random_hash;

fn build_state_hashes() -> Vec<Hash> {
    let count = 10000;
    let mut states = Vec::with_capacity(count);
    for _ in 0..count {
        states.push(random_hash());
    }
    states
}

fn main() {
    let states = build_state_hashes();
    let tmpdir = tempfile::TempDir::new().unwrap();
    let sigmajig = SignerMajig::new(tmpdir.path());
    let mut chain = sigmajig.create_owned_chain(&states[0]).unwrap();

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
}
