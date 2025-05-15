use zf_zebrachain::{BLOCK, MutBlock, PAYLOAD, Payload, Seed};

fn random_payload_buf() -> [u8; PAYLOAD] {
    let mut buf = [0; PAYLOAD];
    getrandom::fill(&mut buf).unwrap();
    buf
}

fn random_payload() -> Payload {
    Payload::from_buf(&random_payload_buf())
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
