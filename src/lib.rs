//! 🦓 🔗 ZebraChain: A futuristic cryptographic identity system.
//!
//! ZebraChain is a logged, quantum safe signing protocol designed to replace the long lived
//! asymmetric key pairs used to sign software releases (and to sign other super important stuff).
//!
//! ZebraChain uses the [NIST post quantum standard][nist.gov] algorithm [ML-DSA] (FIPS-204)
//! alongside [ed25519] in a hybrid signing construction (as recommended by the ML-DSA authors).
//!
//! This is a pre-release crate. The API is still being finalized. A quick-start will be added soon.
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

pub use always::*;
pub use block::{Block, BlockResult, BlockState, MutBlock};
pub use chain::{Chain, ChainIter, ChainStore, CheckPoint};
pub use errors::{BlockError, SecretBlockError};
pub use ownedblock::{MutOwnedBlock, OwnedBlockState, sign};
pub use ownedchain::{OwnedChain, OwnedChainStore};
pub use payload::Payload;
pub use secretblock::{MutSecretBlock, SecretBlock, SecretBlockResult};
pub use secretchain::{SecretChain, SecretChainIter, SecretChainStore};
pub use secretseed::{Error, Secret, Seed, generate_secret};
