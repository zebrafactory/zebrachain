//! Constructs a Block and SecretBlock in-memory.

use crate::block::BlockState;
use crate::block::SigningRequest;
use crate::pksign::sign_block;
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
) -> Hash {
    let block_hash = sign_block(buf, seed, request, None);
    let mut secblock = MutSecretBlock::new(secbuf, seed, request);
    if let OwnedBlockState::Previous(bs, sbs) = prev {
        secblock.set_previous(sbs)
    }
    block_hash
}

#[cfg(test)]
mod tests {
    use super::*;
}
