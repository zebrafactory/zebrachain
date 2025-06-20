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
//! * Changes the keypairs at every signature by including the public key used to sign the current
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
//! This is a nascent implementation of a yet to be finalized protocol. It's also built on a quite new
//! Rust implementation of [ML-DSA] that has its own security warning.
//!
//! ##  🚀 Quickstart
//!
//! ```
//! use tempfile;
//! use zf_zebrachain::{ChainStore, Hash, OwnedChainStore, Payload};
//!
//! // To create a chain and make signatures, you need a directory for your public chain files
//! // and another directory for your secret chain files:
//! let chain_dir = tempfile::TempDir::new().unwrap();
//! let secret_chain_dir = tempfile::TempDir::new().unwrap();
//!
//! // Use both directories in your OwnedChainStore:
//! let owned_store = OwnedChainStore::new(chain_dir.path(), secret_chain_dir.path());
//!
//! // OwnedChainStore.list_chains() will return zero chains (as we haven't created any yet):
//! assert_eq!(owned_store.list_chains().unwrap(), []);
//!
//! // A Payload is what you to sign. Currently it's a 64-bit timestamp and a 320-bit hash. To
//! // create a new chain, you need the first payload that you want to sign:
//! let payload1 = Payload::new_time_stamped(Hash::compute(b"Message number 1"));
//!
//! // Lastly, you need a password (or a key from a hardware security module or similar) that will
//! // be used to encrypt this secret chain:
//! let password = b"SUPER BAD PASSWORD";
//! let mut owned_chain = owned_store.generate_chain(&payload1, password).unwrap();
//! assert_eq!(owned_chain.head().payload, payload1);
//! assert_eq!(owned_chain.tail().payload, payload1);
//!
//! // Make another signature like this:
//! let payload2 = Payload::new_time_stamped(Hash::compute(b"Message number 2"));
//! owned_chain.sign(&payload2).unwrap();
//! assert_eq!(owned_chain.head().payload, payload1);
//! assert_eq!(owned_chain.tail().payload, payload2);
//!
//! // A chain is identified by its `chain_hash`, which is the hash of the 1st block in the chain:
//! let chain_hash = *owned_chain.chain_hash();
//! assert_eq!(chain_hash, owned_chain.head().block_hash);
//!
//! // OwnedChainStore.list_chains() now shows our expected chain:
//! assert_eq!(owned_store.list_chains().unwrap(), [chain_hash]);
//!
//! // Reopen the owned chain and create additional signatures like this:
//! let mut owned_chain = owned_store.open_chain(&chain_hash, password).unwrap();
//! let payload3 = Payload::new_time_stamped(Hash::compute(b"Message number 3"));
//! owned_chain.sign(&payload3).unwrap();
//! assert_eq!(owned_chain.head().payload, payload1);
//! assert_eq!(owned_chain.tail().payload, payload3);
//!
//! // A ChainStore is used for consuming the public side of the chain:
//! let store = ChainStore::new(chain_dir.path());
//!
//! // ChainStore.list_chains() likewise shows our expected chain:
//! assert_eq!(store.list_chains().unwrap(), [chain_hash]);
//!
//! // Open and fully verify the public chain by the `chain_hash` like this:
//! let chain = store.open_chain(&chain_hash).unwrap();
//! assert_eq!(chain.head().payload, payload1);
//! assert_eq!(chain.tail().payload, payload3);
//! ```
//!
//! [ML-DSA]: https://github.com/RustCrypto/signatures/tree/master/ml-dsa

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

pub use always::{
    BLOCK, CONTEXT, DIGEST, PAYLOAD, SECRET, SECRET_BLOCK, SECRET_BLOCK_AEAD, SECRET_CHAIN_HEADER,
};
pub use block::{Block, BlockState, CheckPoint, MutBlock, sign_block};
pub use chain::{Chain, ChainIter, ChainStore};
pub use errors::{BlockError, EntropyError, SecretBlockError};
pub use hashing::{Hash, HexError, Secret, SubSecret, SubSecret192, SubSecret256};
pub use ownedblock::{MutOwnedBlock, OwnedBlockState};
pub use ownedchain::{OwnedChain, OwnedChainStore};
pub use payload::Payload;
pub use secretblock::{MutSecretBlock, SecretBlock, SecretBlockState};
pub use secretchain::{SecretChain, SecretChainHeader, SecretChainIter, SecretChainStore};
pub use secretseed::Seed;
