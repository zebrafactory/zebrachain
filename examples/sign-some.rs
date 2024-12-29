use blake3::Hash;
use getrandom::getrandom;
use std::io::prelude::*;
use tempfile;
use zebrachain::chain::Chain;
use zebrachain::pksign::SigningChain;
use zebrachain::secretseed::Seed;

fn main() {
    let mut entropy = [0; 32];
    getrandom(&mut entropy).unwrap();
    let mut seed = Seed::create(&entropy);
    entropy.fill(0);
    let mut states: Vec<Hash> = Vec::new();
    for i in 0u8..=255 {
        states.push(Hash::from_bytes([i; 32]));
    }

    let mut file = tempfile::tempfile().unwrap();
    let mut sc = SigningChain::start(&seed, &states[0]);
    file.write_all(sc.as_buf()).unwrap();
    file.rewind().unwrap();
    let mut chain = Chain::open(file).unwrap();
    for state_hash in &states[1..] {
        getrandom(&mut entropy).unwrap();
        let next = seed.advance(&entropy);
        sc.sign(&next, &state_hash);
        chain.append(sc.as_buf());
        println!("{} {}", chain.state.tail.block_hash, state_hash);
        seed.commit(next);
    }
}
