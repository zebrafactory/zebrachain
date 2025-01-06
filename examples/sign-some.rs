use blake3::Hash;
use std::io::prelude::*;
use tempfile;
use zebrachain::always::*;
use zebrachain::chain::{Chain, ChainStore};
use zebrachain::pksign::{create_first_block, SigningChain};
use zebrachain::secretchain::SecretChainStore;
use zebrachain::secretseed::{random_hash, Seed};

fn build_state_hashes() -> Vec<Hash> {
    let count = 10000;
    let mut states = Vec::with_capacity(count);
    for i in 0..count {
        states.push(random_hash());
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
    let chain_hash = block.chain_hash();
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
    let chain_hash = chain.state.head.block_hash;
    let mut chain = cs.open_chain(&chain_hash).unwrap();
    chain.validate().unwrap();

    let tmpdir2 = tempfile::TempDir::new().unwrap();
    let scs = SecretChainStore::new(tmpdir2.path().to_path_buf());
    let seed = Seed::auto_create();
    let chain_hash = Hash::from_bytes([42; 32]);
    let state_hash = Hash::from_bytes([69; 32]);
    let mut secretchain = scs.create_chain(&chain_hash, seed, &state_hash).unwrap();
    for state_hash in states {
        let next = secretchain.auto_advance();
        secretchain.commit(next, &state_hash).unwrap();
    }
}

/*
Create new chain:
1. create seed
2. construct first block in memory (sign and hash)
3. use block hash hex to name chain file
4. open file
5. write first block
*/
