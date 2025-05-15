use zf_zebrachain::{BLOCK, Block, BlockError, DIGEST, Hash, MutBlock, PAYLOAD, Payload, Seed};

fn random_payload_buf() -> [u8; PAYLOAD] {
    let mut buf = [0; PAYLOAD];
    getrandom::fill(&mut buf).unwrap();
    buf
}

fn random_payload() -> Payload {
    Payload::from_buf(&random_payload_buf())
}

#[test]
fn test_block() {
    let buf = [0; BLOCK];
    let block = Block::new(&buf);
    let block_hash = Hash::from_bytes([69; DIGEST]);
    assert_eq!(
        block.from_hash_at_index(&block_hash, 0),
        Err(BlockError::Content)
    );

    let mut buf = [0; BLOCK];

    let payload_0 = random_payload();
    let seed = Seed::auto_create().unwrap();
    let mut mblock = MutBlock::new(&mut buf, &payload_0);
    mblock.sign(&seed);
    let block_hash_0 = mblock.finalize();
    let block = Block::new(&buf);
    let block_state_0 = block.from_hash_at_index(&block_hash_0, 0).unwrap();

    let payload_1 = random_payload();
    let seed = seed.auto_advance().unwrap();
    let mut mblock = MutBlock::new(&mut buf, &payload_1);
    mblock.set_previous(&block_state_0);
    mblock.sign(&seed);
    let block_hash_1 = mblock.finalize();
    let block = Block::new(&buf);
    let block_state_1 = block.from_hash_at_index(&block_hash_1, 1).unwrap();
    let block = Block::new(&buf);
    assert_eq!(block.from_previous(&block_state_0).unwrap(), block_state_1);
    let block = Block::new(&buf);
    assert_eq!(
        block.from_previous(&block_state_1),
        Err(BlockError::PubKeyHash)
    );
}

#[test]
fn test_mutblock() {
    let payload = random_payload();
    let seed = Seed::auto_create().unwrap();
    let mut buf = [0; BLOCK];
    let mut block = MutBlock::new(&mut buf, &payload);
    block.sign(&seed);
    let block_hash = block.finalize();
    assert_ne!(buf, [0; BLOCK]);
    assert!(buf.starts_with(block_hash.as_bytes()));
}
