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

use crate::block::{BlockState, MutBlock};
use crate::payload::Payload;
use crate::pksign::SecretSigner;
use crate::secretblock::{MutSecretBlock, SecretBlockState};
use crate::secretchain::derive_chain_secret;
use crate::secretseed::{Secret, Seed};
use blake3::Hash;

/// Combines [BlockState] and [SecretBlockState].
pub struct OwnedBlockState {
    /// The public block state.
    pub block_state: BlockState,

    /// The secret block state.
    pub secret_block_state: SecretBlockState,
}

impl OwnedBlockState {
    /// Return a new [OwnedBlockState].
    pub fn new(block_state: BlockState, secret_block_state: SecretBlockState) -> Self {
        Self {
            block_state,
            secret_block_state,
        }
    }
}

/// Builds up both public and secret block for new block being signed.
pub struct MutOwnedBlock<'a> {
    block: MutBlock<'a>,
    secret_block: MutSecretBlock<'a>,
}

impl<'a> MutOwnedBlock<'a> {
    /// Zero buffers and set payload in both public and secret buffers.
    pub fn new(buf: &'a mut [u8], secret_buf: &'a mut Vec<u8>, payload: &Payload) -> Self {
        let block = MutBlock::new(buf, payload);
        let secret_block = MutSecretBlock::new(secret_buf, payload);
        Self {
            block,
            secret_block,
        }
    }

    /// Set current public and secret block states based on previous [OwnedBlockState].
    pub fn set_previous(&mut self, prev: &OwnedBlockState) {
        self.block.set_previous(&prev.block_state);
        self.secret_block.set_previous(&prev.secret_block_state);
    }

    /// Sign public block using `seed` and then save seed in secret block.
    pub fn sign(&mut self, seed: &Seed) {
        let signer = SecretSigner::new(seed);
        signer.sign(&mut self.block);
        self.secret_block.set_seed(seed);
    }

    /// Finalize both public and secret blocks, returning their hashes.
    pub fn finalize(mut self, chain_secret: &Secret) -> (Hash, Hash) {
        let block_hash = self.block.finalize();
        self.secret_block.set_public_block_hash(&block_hash);
        let secret_block_hash = self.secret_block.finalize(chain_secret);
        (block_hash, secret_block_hash)
    }

    /// FIXME: Kinda hacky, but works for now.
    pub fn finalize_first(mut self, store_secret: &Secret) -> (Hash, Hash) {
        let chain_hash = self.block.finalize();
        self.secret_block.set_public_block_hash(&chain_hash);
        let chain_secret = derive_chain_secret(store_secret, &chain_hash);
        let secret_block_hash = self.secret_block.finalize(&chain_secret);
        (chain_hash, secret_block_hash)
    }
}

/// High-level signing function.
pub fn sign(
    buf: &mut [u8],
    secret_buf: &mut Vec<u8>,
    chain_secret: &Secret,
    seed: &Seed,
    payload: &Payload,
    prev: Option<OwnedBlockState>,
) -> (Hash, Hash) {
    let mut block = MutOwnedBlock::new(buf, secret_buf, payload);
    if let Some(obs) = prev.as_ref() {
        block.set_previous(obs);
    }
    block.sign(seed);
    if let Some(obs) = prev.as_ref() {
        assert_eq!(
            obs.block_state.next_pubkey_hash,
            block.block.compute_pubkey_hash()
        );
    }
    block.finalize(chain_secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::always::*;
    use crate::block::Block;
    use crate::pksign;
    use crate::secretseed::generate_secret;
    use crate::testhelpers::random_payload;

    #[test]
    fn test_sign() {
        let chain_secret = generate_secret().unwrap();
        let seed = Seed::auto_create().unwrap();
        let payload = random_payload();
        let mut buf = [0; BLOCK];
        let mut secret_buf = vec![0; SECRET_BLOCK];
        let (block_hash, _) = sign(
            &mut buf,
            &mut secret_buf,
            &chain_secret,
            &seed,
            &payload,
            None,
        );
        assert!(Block::from_hash_at_index(&buf, &block_hash, 0).is_ok());
        assert_eq!(
            pksign::sign_block(&mut buf, &seed, &payload, None),
            block_hash
        );
    }
}
