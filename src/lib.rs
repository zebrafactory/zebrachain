//! 🦓 🔗 ZebraChain: A futuristic cryptographic identity system.
//!
//! ZebraChain is a logged, quantum safe signing protocol designed to replace the long lived
//! asymmetric key pairs used to sign software releases (and to sign other super important stuff).
//!
//! ZebraChain uses the [NIST post quantum standard][nist.gov] algorithm [Dilithium] alongside
//! [ed25519] in a hybrid signing construction (as recommended by the Dilithium authors).
//!
//! [nist.gov]: https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards
//! [Dilithium]: https://pq-crystals.org/dilithium/
//! [ed25519]: https://ed25519.cr.yp.to/

pub mod always;
pub mod block;
pub mod chain;
pub mod fsutil;
pub mod ownedchain;
pub mod pksign;
pub mod secretblock;
pub mod secretchain;
pub mod secretseed;

#[cfg(test)]
pub mod testhelpers;
