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
use crate::secretblock::{MutSecretBlock, SecretBlockState};
use crate::secretseed::Seed;
use blake3::Hash;

pub struct OwnedBlockState {
    block_state: BlockState,
    secret_block_state: SecretBlockState,
}

impl OwnedBlockState {
    pub fn new(block_state: BlockState, secret_block_state: SecretBlockState) -> Self {
        Self {
            block_state,
            secret_block_state,
        }
    }

    pub fn block_state(&self) -> &BlockState {
        &self.block_state
    }

    pub fn secret_block_state(&self) -> &SecretBlockState {
        &self.secret_block_state
    }
}

pub struct MutOwnedBlock<'a> {
    pub block: MutBlock<'a>,
    pub secret_block: MutSecretBlock<'a>,
}

impl<'a> MutOwnedBlock<'a> {
    pub fn new(
        buf: &'a mut [u8],
        secret_buf: &'a mut [u8],
        request: &SigningRequest,
        seed: &Seed,
    ) -> Self {
        let block = MutBlock::new(buf, request);
        let secret_block = MutSecretBlock::new(secret_buf, seed, request);
        Self {
            block,
            secret_block,
        }
    }

    pub fn set_previous(&mut self, prev: &OwnedBlockState) {
        self.block.set_previous(prev.block_state());
        self.secret_block.set_previous(prev.secret_block_state());
    }

    pub fn finalize(mut self) -> (Hash, Hash) {
        let block_hash = self.block.finalize();
        // FIXME: We should probably include the resulting public block hash in the secret block,
        // so set that here before calling MutSecretBlock.finalize().
        let secret_block_state = self.secret_block.finalize();
        (block_hash, secret_block_state.block_hash)
    }
}

pub fn sign(
    seed: &Seed,
    request: &SigningRequest,
    buf: &mut [u8],
    secret_buf: &mut [u8],
    prev: Option<OwnedBlockState>,
) -> (Hash, Hash) {
    let mut block = MutOwnedBlock::new(buf, secret_buf, request, seed);
    if let Some(obs) = prev.as_ref() {
        block.set_previous(&obs);
    }
    let signer = SecretSigner::new(seed);
    signer.sign(&mut block.block);
    if let Some(obs) = prev.as_ref() {
        assert_eq!(
            obs.block_state().next_pubkey_hash,
            block.block.compute_pubkey_hash()
        );
    }
    block.finalize()
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
        let (block_hash, _) = sign(&seed, &req, &mut buf, &mut secbuf, None);
        assert!(Block::from_hash_at_index(&buf, &block_hash, 0).is_ok());
        assert_eq!(pksign::sign_block(&mut buf, &seed, &req, None), block_hash);
    }
}
