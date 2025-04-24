#![deny(missing_docs)]

//! 🦓 🔗 ZebraChain: A futuristic cryptographic identity system.
//!
//! ZebraChain is a logged, quantum safe signing protocol designed to replace the long lived
//! asymmetric key pairs used to sign software releases (and to sign other super important stuff).
//!
//! ZebraChain uses the [NIST post quantum standard][nist.gov] algorithm [ML-DSA] (FIPS-204)
//! alongside [ed25519] in a hybrid signing construction (as recommended by the ML-DSA authors).
//!
//! This is a pre-release crate. The API is still being finalized.
//!
//! # Quickstart
//!
//! ```
//! use blake3::Hash;
//! use tempfile;
//! use zf_zebrachain::{OwnedChainStore, Payload, generate_secret};
//!
//! // Chains you can create signatures for are "owned":
//! let chain_dir = tempfile::TempDir::new().unwrap();
//! let secret_chain_dir = tempfile::TempDir::new().unwrap();
//! let storage_secret = generate_secret().unwrap();
//! let mystore = OwnedChainStore::build(
//!     chain_dir.path(), secret_chain_dir.path(), storage_secret
//! );
//!
//! // A Payload is what you to sign. Currently it's a 64-bit timestamp and a 256-bit hash. To
//! // create a new chain, you need the first payload you want to sign:
//! let p1 = Payload::new(123, Hash::from_bytes([42; 32]));
//!
//! // To create a new chain, you also need the initial entropy used for the chain:
//! let initial_entropy = generate_secret().unwrap();
//!
//! // Create a chain, the first block of which will contained the signed payload:
//! let mut mychain = mystore.create_chain(&initial_entropy, &p1).unwrap();
//!
//! // Create next signature in the chain.
//! let p2 = Payload::new(456, Hash::from_bytes([69; 32]));
//! let new_entropy = generate_secret().unwrap();
//! mychain.sign(&new_entropy, &p2);
//! ```
//!
//! [nist.gov]: https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards
//! [ML-DSA]: https://csrc.nist.gov/pubs/fips/204/final
//! [ed25519]: https://ed25519.cr.yp.to/

mod always;
mod block;
mod chain;
mod errors;
mod fsutil;
mod ownedblock;
mod ownedchain;
mod payload;
mod pksign;
mod secretblock;
mod secretchain;
mod secretseed;

#[cfg(test)]
pub mod testhelpers;

pub use always::{BLOCK, PAYLOAD};
pub use block::{Block, BlockResult, BlockState, MutBlock};
pub use chain::{Chain, ChainIter, ChainStore, CheckPoint};
pub use errors::{BlockError, SecretBlockError};
pub use ownedblock::{MutOwnedBlock, OwnedBlockState, sign};
pub use ownedchain::{OwnedChain, OwnedChainStore};
pub use payload::Payload;
pub use secretblock::{MutSecretBlock, SecretBlock, SecretBlockResult, SecretBlockState};
pub use secretchain::{SecretChain, SecretChainIter, SecretChainStore};
pub use secretseed::{Error, Secret, Seed, generate_secret};
