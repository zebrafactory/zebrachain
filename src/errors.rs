//! Errors, yo!

use std::io;

/// Expresses different error conditions hit during block validation.
#[derive(Debug, PartialEq)]
pub enum BlockError {
    /// Hash of block content does not match hash in block.
    Content,

    /// Public key or signature is invalid.
    Signature,

    /// Hash in block does not match expected external value.
    Hash,

    /// Hash of public key bytes does not match expected external value.
    PubKeyHash,

    /// Previous hash does not match expected external value.
    PreviousHash,

    /// Chain hash does not match expected external value.
    ChainHash,

    /// Index does not match expected external value (previous block index + 1).
    Index,

    /// First block does not meet 1st block constraints
    FirstBlock,
}

impl BlockError {
    // FIXME: Is there is a Rustier way of doing this? Feedback encouraged.
    pub fn to_io_error(&self) -> io::Error {
        io::Error::other(format!("BlockError::{self:?}"))
    }
}

/// Expresses different error conditions hit when validating a [SecretBlock].
#[derive(Debug, PartialEq)]
pub enum SecretBlockError {
    /// Hash of block content does not match hash in block.
    Content,

    /// Block contains a bad seed where `secret == next_secret`.
    Seed,

    /// Block is out of sequence (`seed.secret != previous.next_secret`).
    SeedSequence,

    /// Hash in block does not match expected external value.
    Hash,

    /// Block index is wrong.
    Index,

    /// Previous hash in block does not match expected external value.
    PreviousHash,

    /// Failure decrypting the secret block (chacha20poly1305).
    Storage,
}

impl SecretBlockError {
    // FIXME: Is there is a Rustier way of doing this? Feedback encouraged.
    pub fn to_io_error(&self) -> io::Error {
        io::Error::other(format!("SecretBlockError::{self:?}"))
    }
}
