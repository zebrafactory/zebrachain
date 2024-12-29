use blake3::Hash;
use std::io::prelude::*;
use tempfile;
use zebrachain::chain::Chain;
use zebrachain::pksign::SigningChain;
use zebrachain::secretseed::Seed;

fn main() {
    let initial_entropy = [69; 32];
    let new_entropy = [42; 32];
    let mut seed = Seed::create(&initial_entropy);
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
        let next = seed.advance(&new_entropy);
        sc.sign(&next, &state_hash);
        chain.append(sc.as_buf());
        println!("{}", chain.state.tail.block_hash);
        seed.commit(next);
    }
}
