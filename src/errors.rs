//! Errors, yo!

use std::io;

/// Error conditions hit when validating a [Block][crate::block::Block].
#[derive(Debug, PartialEq)]
pub enum BlockError {
    /// Hash of block content does not match hash in block.
    Content,

    /// Public key or signature is invalid.
    Signature,

    /// Block hash does not match expected external value.
    BlockHash,

    /// Hash of public key bytes does not match expected external value.
    PubKeyHash,

    /// Previous hash does not match expected external value.
    PreviousHash,

    /// Chain hash does not match expected external value.
    ChainHash,

    /// Index does not match expected external value (previous block index + 1).
    BlockIndex,

    /// First block does not meet 1st block constraints
    FirstBlock,
}

impl BlockError {
    /// Map into an io Error with appropriate msg text.
    pub fn to_io_error(&self) -> io::Error {
        io::Error::other(format!("BlockError::{self:?}"))
    }
}

/// Error conditions hit when validating a [SecretBlock][crate::secretblock::SecretBlock].
#[derive(Debug, PartialEq)]
pub enum SecretBlockError {
    /// Authenticated decryption of the secret block failed.
    Decryption,

    /// Hash of block content does not match hash in block.
    Content,

    /// Block contains a bad seed where `secret == next_secret`.
    Seed,

    /// Block is out of sequence (`seed.secret != previous.next_secret`).
    SeedSequence,

    /// Hash in block does not match expected external value.
    Hash,

    /// Block index is wrong.
    BlockIndex,

    /// Previous hash in block does not match expected external value.
    PreviousHash,
}

impl SecretBlockError {
    /// Map into an io Error with appropriate msg text.
    pub fn to_io_error(&self) -> io::Error {
        io::Error::other(format!("SecretBlockError::{self:?}"))
    }
}

/// Error equivalent to gettrandom::Error.
#[derive(Debug)]
pub struct EntropyError {
    inner: getrandom::Error,
}

impl EntropyError {
    /// Create a new `EntropyError`.
    pub fn new(inner: getrandom::Error) -> Self {
        Self { inner }
    }

    /// Map into an io Error with appropriate msg text.
    pub fn to_io_error(&self) -> io::Error {
        io::Error::other(format!("EntropyError({:?})", self.inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blockerror_to_io_error() {
        assert_eq!(
            format!("{:?}", BlockError::Content.to_io_error()),
            "Custom { kind: Other, error: \"BlockError::Content\" }"
        );
        assert_eq!(
            format!("{:?}", BlockError::Signature.to_io_error()),
            "Custom { kind: Other, error: \"BlockError::Signature\" }"
        );
    }

    #[test]
    fn test_secretblockerror_to_io_error() {
        assert_eq!(
            format!("{:?}", SecretBlockError::Decryption.to_io_error()),
            "Custom { kind: Other, error: \"SecretBlockError::Decryption\" }"
        );
        assert_eq!(
            format!("{:?}", SecretBlockError::SeedSequence.to_io_error()),
            "Custom { kind: Other, error: \"SecretBlockError::SeedSequence\" }"
        );
    }
}
