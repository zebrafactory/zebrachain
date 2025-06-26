use std::path::PathBuf;
use zf_zebrachain::{BLOCK, Hash, MutBlock, OwnedChainStore, Payload, Secret, Seed};

fn short_password() -> [u8; 5] {
    let mut password = [0; 5];
    getrandom::fill(&mut password).unwrap();
    password
}

fn write_result(initial_entropy: &Secret, payload: &Payload) {
    let dir = PathBuf::from("target/chain");
    let store = OwnedChainStore::new(&dir, &dir);
    let chain = store
        .create_chain(initial_entropy, payload, &short_password())
        .unwrap();
    let chain_hash = chain.chain_hash();
    println!("{chain_hash}");
}

fn main() {
    let payload = Payload::new_time_stamped(Hash::compute(b"Ping"));
    let initial_entropy = Secret::generate().unwrap();
    let mut buf = [0; BLOCK];
    let mut count = 0;
    loop {
        let initial_entropy = initial_entropy.mix(&Secret::generate().unwrap());
        let seed = Seed::create(&initial_entropy);
        let mut block = MutBlock::new(&mut buf, &payload);
        block.sign(&seed);
        let chain_hash = block.finalize();
        let z32 = chain_hash.to_z32();
        if &z32[0..5] == b"ZEBRA" {
            println!("{chain_hash} {count}");
            write_result(&initial_entropy, &payload);
        }
        count += 1;
    }
}
