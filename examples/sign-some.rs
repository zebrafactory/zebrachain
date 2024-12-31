use blake3::Hash;
use std::io::prelude::*;
use tempfile;
use zebrachain::always::*;
use zebrachain::chain::{Chain, ChainStore};
use zebrachain::pksign::{create_first_block, SigningChain};
use zebrachain::secretseed::Seed;

fn build_state_hashes() -> Vec<Hash> {
    let mut states = Vec::new();
    for i in 0u8..=255 {
        states.push(Hash::from_bytes([i; 32]));
    }
    states
}

fn main() {
    let states = build_state_hashes();
    let tmpdir = tempfile::TempDir::new().unwrap();
    let cs = ChainStore::new(tmpdir.path().to_path_buf());

    let mut seed = Seed::auto_create();
    let mut buf = [0; BLOCK];
    let block = create_first_block(&mut buf, &seed, &states[0]);
    let mut chain = cs.create_chain(&block).unwrap();
    let mut sc = SigningChain::resume(block.state());

    println!(
        "{} {} {}",
        chain.state.tail.chain_hash, chain.state.tail.block_hash, &states[0]
    );
    for state_hash in &states[1..] {
        let next = seed.auto_advance();
        sc.sign(&next, &state_hash);
        chain.append(sc.as_buf()).unwrap();
        println!(
            "{} {} {}",
            chain.state.tail.chain_hash, chain.state.tail.block_hash, state_hash
        );
        seed.commit(next);
    }
    let mut file = chain.into_file();
    file.rewind().unwrap();
    let mut chain = Chain::open(file).unwrap();
    chain.validate().unwrap();
}

/*
Create new chain:
1. create seed
2. construct first block in memory (sign and hash)
3. use block hash hex to name chain file
4. open file
5. write first block
*/
