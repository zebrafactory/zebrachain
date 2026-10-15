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
    /// Consume instance and use as inner value for `io::Error`.
    pub fn into_io_error(self) -> io::Error {
        io::Error::other(self)
    }
}

impl core::fmt::Display for BlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(&format!("BlockError::{self:?}"))
    }
}

impl core::error::Error for BlockError {}

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

    /// Header at start of chain is malformed
    ChainHeader,
}

impl SecretBlockError {
    /// Consume instance and use as inner value for `io::Error`.
    pub fn into_io_error(self) -> io::Error {
        io::Error::other(self)
    }
}

impl core::fmt::Display for SecretBlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(&format!("SecretBlockError::{self:?}"))
    }
}

impl core::error::Error for SecretBlockError {}

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

    /// Consume instance and use as inner value for `io::Error`.
    pub fn into_io_error(self) -> io::Error {
        io::Error::other(self)
    }
}

impl core::fmt::Display for EntropyError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(&format!("EntropyError::{:?}", self.inner))
    }
}

impl core::error::Error for EntropyError {}

/// Errors encountered when validating or modifying `Permission`.
#[derive(Debug, PartialEq)]
pub enum PermissionError {
    /// There are zero permissions set in the `GroupPermissions`,
    Empty,

    /// Length of permissions buffer is wrong.
    BufferLength,

    /// User already has a public key in the permissions object.
    EmptyBuffer,

    /// fixme.
    Duplicate,

    /// FIXME
    Hash,

    /// FIXME
    Size,

    /// FIXME
    Header,
}

impl PermissionError {
    /// Consume instance and use as inner value for `io::Error`.
    pub fn into_io_error(self) -> io::Error {
        io::Error::other(self)
    }
}

impl core::fmt::Display for PermissionError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(&format!("PermissionError::{self:?}"))
    }
}

impl core::error::Error for PermissionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blockerror_display_fmt() {
        let err = BlockError::Content;
        assert_eq!(format!("{err}"), "BlockError::Content");
        let err = BlockError::Signature;
        assert_eq!(format!("{err}"), "BlockError::Signature");
    }

    #[test]
    fn test_secretblockerror_display_fmt() {
        let err = SecretBlockError::Decryption;
        assert_eq!(format!("{err}"), "SecretBlockError::Decryption");
        let err = SecretBlockError::SeedSequence;
        assert_eq!(format!("{err}"), "SecretBlockError::SeedSequence");
    }

    #[test]
    fn test_permissionerror_display_fmt() {
        let err = PermissionError::Empty;
        assert_eq!(format!("{err}"), "PermissionError::Empty");
        let err = PermissionError::BufferLength;
        assert_eq!(format!("{err}"), "PermissionError::BufferLength");
    }
}
