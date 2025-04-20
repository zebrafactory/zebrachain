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

pub mod always;
pub mod block;
pub mod chain;
pub mod errors;
pub mod fsutil;
pub mod ownedblock;
pub mod ownedchain;
pub mod payload;
pub mod pksign;
pub mod secretblock;
pub mod secretchain;
pub mod secretseed;

#[cfg(test)]
pub mod testhelpers;
