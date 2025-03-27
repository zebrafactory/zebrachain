//! Constructs a Block and SecretBlock in-memory.

/*
We want signing to have robust transactionality using the following sequence:

1. Get new entropy from the OS CSPRNG (can FAIL!)

2. Create an initial seed or advace the seed

3. Create and sign the public block

4. Create the secret block

5. Write secret block (can FAIL!) [If this succeeds, signing is considered commplete, otherwise rollback]

6. Write public block (can FAIL!)

Because the public block can be recreated from the secret block, this gives us a nice double commit.
*/

use crate::block::{BlockState, MutBlock, SigningRequest};
use crate::pksign::SecretSigner;
use crate::secretblock::{MutSecretBlock, SecretBlock};
use crate::secretseed::Seed;
use blake3::Hash;

pub enum OwnedBlockState<'a> {
    Start,
    Previous(&'a BlockState, &'a SecretBlock),
}

pub fn sign(
    seed: &Seed,
    request: &SigningRequest,
    buf: &mut [u8],
    secbuf: &mut [u8],
    prev: OwnedBlockState,
) -> (Hash, SecretBlock) {
    let mut block = MutBlock::new(buf, request);
    let mut secblock = MutSecretBlock::new(secbuf, seed, request);
    if let OwnedBlockState::Previous(block_state, secret_block_state) = prev {
        block.set_previous(block_state);
        secblock.set_previous(secret_block_state);
    }
    let signer = SecretSigner::new(seed);
    signer.sign(&mut block);
    if let OwnedBlockState::Previous(block_state, _) = prev {
        assert_eq!(block_state.next_pubkey_hash, block.compute_pubkey_hash());
    }
    let block_hash = block.finalize();
    let secret_block_state = secblock.finalize();
    (block_hash, secret_block_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::always::*;
    use crate::block::Block;
    use crate::pksign;
    use crate::testhelpers::random_request;

    #[test]
    fn test_sign() {
        let seed = Seed::auto_create().unwrap();
        let req = random_request();
        let mut buf = [0; BLOCK];
        let mut secbuf = [0; SECRET_BLOCK];
        let prev = OwnedBlockState::Start;
        let (block_hash, _) = sign(&seed, &req, &mut buf, &mut secbuf, prev);
        assert!(Block::from_hash_at_index(&buf, &block_hash, 0).is_ok());
        assert_eq!(pksign::sign_block(&mut buf, &seed, &req, None), block_hash);
    }
}
