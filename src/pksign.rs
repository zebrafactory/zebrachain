//! Abstraction over public key signature algorithms.

use blake3;
use ed25519_dalek::{Signer};

static ED25519_CONTEXT: &str = "win.zebrachain.sign.ed25519";

/*
We need public key signing systems with this deterministic flow:

ENCRYPTED_SECRET --> SECRET --> DERIVED_SECRET --> (SECRET_KEY, PUBLIC_KEY)

You can do this with most (all?) algorithms (even RSA), but Dilithium and
ed25519 are both extra great for this.

In order to make the next signature in the chain, we need to:

1.  Decrypt secret.

2.  Derive context secret with, eg, blake3::Hasher::new_derived key().  Note
    that in a Dilithium + ed25519 hybrid construction, each algorithm MUST
    derive their own key with their own unique context string.

3.  Deterministicly generate the algorithm-specific (secret, private) key pair
    from the derived secret (eg, the Dilithium or ed25519 keypair).  There is no
    reason to ever expose details of secret signing key type or its bytes
    outside the KeyPair.  We do need to expose the public key bytes to the outside,
    though.

4.  Generate the

*/

/// Trait to expose the needed bits of a (secret, private) keypair.
///
/// Remember that a `KeyPair` could be a Dilithium + ed25519 hybrid pair.
pub trait KeyPair {
    /// We need deterministic KeyPair generation from the same secret.
    ///
    /// This should work from an arbitrary secret and

    fn derive(secret: &[u8]) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new_derive_key(Self::get_context());
        hasher.update(secret);
        hasher.finalize()
    }

    fn new(secret: &[u8]) -> impl KeyPair {
        Self::new_derived(Self::derive(secret))
    }

    fn get_context() -> &'static str;

    fn new_derived(derived: blake3::Hash) -> impl KeyPair;

    /// Write public key into byte slice.
    fn write_pubkey(&self, dst: &mut [u8]);

    /// Sign message.
    fn sign(self, msg: &[u8], dst: &mut [u8]);
}

pub enum Error {
    MalformedPublicKey,
    MalformedSignature,
    InvalidSignature,
}

pub trait PubKey {
    fn verify(pubkey: &[u8], sig: &[u8], msg: &[u8]) -> Result<(), Error>;
}




struct Ed25519 {
    key: ed25519_dalek::SigningKey,
}

impl KeyPair for Ed25519 {
    fn get_context() -> &'static str {
        ED25519_CONTEXT
    }

    fn new_derived(derived: blake3::Hash) -> Ed25519 {
        let key = ed25519_dalek::SigningKey::from_bytes(derived.as_bytes());
        Ed25519 {key}
    }
 
    fn write_pubkey(&self, dst: &mut [u8]) {
        dst.copy_from_slice(self.key.verifying_key().as_bytes());
    }

    fn sign(self, msg: &[u8], dst: &mut [u8]) {
        let sig = self.key.sign(msg);
        dst.copy_from_slice(&sig.to_bytes());
    }
}


impl PubKey for Ed25519 {
    fn verify(pubkey: &[u8], sig: &[u8], msg: &[u8]) -> Result<(), Error> {
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_new() {
        let secret = [7; 32];
        let pair = Ed25519::new(&secret);

        let mut pubkey = [0; 32];
        pair.write_pubkey(&mut pubkey);

        let msg = b"hello all the world, yo!";
        let mut sig = [0; 64];
        pair.sign(msg, &mut sig);
    }
}
