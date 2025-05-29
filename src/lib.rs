#![deny(missing_docs)]

//! # 🦓 🔗 ZebraChain: A futuristic cryptographic identity system.
//!
//! ZebraChain is a logged, quantum safe signing protocol designed to replace the long lived
//! asymmetric key pairs used to sign software releases (and to sign other super important stuff).
//!
//! In short, ZebraChain:
//!
//! * Logs each signature in a block chain
//!
//! * Rotates the keypairs at every signature by including the public key used to sign the current
//!   block and the hash of the public key that will be used to sign the next block
//!
//! * Is quantum secure because it uses ML-DSA + ed25519 in a hybrid signing construction (as
//!   recommended by the ML-DSA authors)
//!
//! This is a pre-release crate. The API is still being finalized. The 0.0.x releases make no
//! API commitments, nor any commits to the protocol.
//!
//! However, the dust is settling quickly and it's a perfect time to jump in and start building
//! experimental applications on top of ZebraChain!
//!
//! ## ⚠️ Security Warning
//!
//! ZebraChain is not yet suitable for production use.
//!
//! This is a nascent implementation of a yet to be finalized protocol. It's also built an quite
//! new Rust implementations of [ML-DSA] and [SLH-DSA].
//!
//! ##  🚀 Quickstart
//!
//! ```
//! use tempfile;
//! use zf_zebrachain::{ChainStore, OwnedChainStore, Hash, Payload, Secret};
//!
//! // Chains are just files in a directory (for now). To get started you need a directory for
//! // your public chain files and a `ChainStore`:
//! let chain_dir = tempfile::TempDir::new().unwrap();
//! let store = ChainStore::new(chain_dir.path());
//!
//! // To create signatures in a chain that you own, you also need a directory for your secret
//! // chain files and a secret storage key that will be used to encrypt them:
//! let secret_chain_dir = tempfile::TempDir::new().unwrap();
//! let storage_secret = Secret::generate().unwrap(); // Uses getrandom::fill()
//! let mystore = OwnedChainStore::build(
//!     chain_dir.path(), secret_chain_dir.path(), storage_secret
//! );
//!
//! // A Payload is what you to sign. Currently it's a 128-bit timestamp and a 256-bit hash. To
//! // create a new chain, you need the first payload that you want to sign:
//! let payload1 = Payload::new(123, Hash::from_bytes([42; 32]));
//!
//! // Create a chain, the first block of which will contain the signed payload. The first block
//! // is signed with the 1st keypair, but the hash of the public key of the 2nd keypair is
//! // included in the 1st block. This is the forward contract for the keypair that will be used
//! // to sign the next block. OwnedChainStore.auto_create_chain() internally generates the
//! // needed initial entropy.
//! let mut mychain = mystore.auto_create_chain(&payload1).unwrap();
//! assert_eq!(mychain.tail().payload, payload1);
//!
//! // Let us sign another payload. Each signatures requires new entropy, which is mixed into the
//! // the secret chain state using a keyed hash. This latest seed will be used to create a 3rd
//! // keypair, and the hash of its public key is included this block. The 2nd block is signed with
//! // the 2nd keypair created above. OwnedChain.auto_sign() internally generates the needed new
//! // entropy.
//! let payload2 = Payload::new(456, Hash::from_bytes([69; 32]));
//! mychain.auto_sign(&payload2);
//! assert_eq!(mychain.tail().payload, payload2);
//!
//! // A chain is identified by its `chain_hash`, which is the hash of the 1st block in the chain:
//! let chain_hash = mychain.chain_hash();
//!
//! // We can now open that chain from the public chain store, which will fully validate the chain
//! // and set the tail at the latest block:
//! let chain = store.open_chain(&chain_hash).unwrap();
//! assert_eq!(chain.head().payload, payload1);
//! assert_eq!(chain.tail().payload, payload2);
//! ```
//!
//! [ML-DSA]: https://github.com/RustCrypto/signatures/tree/master/ml-dsa
//! [SLH-DSA]: https://github.com/RustCrypto/signatures/tree/master/slh-dsa

mod always;
mod block;
mod chain;
mod errors;
mod fsutil;
mod hashing;
mod ownedblock;
mod ownedchain;
mod payload;
mod pksign;
mod secretblock;
mod secretchain;
mod secretseed;

#[cfg(test)]
pub mod testhelpers;

pub use always::{BLOCK, DIGEST, PAYLOAD, SECRET};
pub use block::{Block, BlockState, CheckPoint, MutBlock, sign_block};
pub use chain::{Chain, ChainIter, ChainStore};
pub use errors::{BlockError, SecretBlockError};
pub use hashing::{EntropyError, Hash, Secret, hash, keyed_hash};
pub use ownedblock::{MutOwnedBlock, OwnedBlockState};
pub use ownedchain::{OwnedChain, OwnedChainStore};
pub use payload::Payload;
pub use secretblock::{MutSecretBlock, SecretBlock, SecretBlockState};
pub use secretchain::{SecretChain, SecretChainIter, SecretChainStore};
pub use secretseed::Seed;
