//! Abstraction over public key signature algorithms.

use blake3;
use ed25519_dalek::{
    SigningKey,
    Signer,
    Signature,
    SignatureError,
    VerifyingKey,
    Verifier,
};

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

struct KeyPair {
    key: ed25519_dalek::SigningKey,
}

impl KeyPair {
    fn new(secret: &[u8]) -> Self {
        Self::new_derived(Self::derive(secret))
    }

    fn derive(secret: &[u8]) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new_derive_key(Self::get_context());
        hasher.update(secret);
        hasher.finalize()
    }

    fn get_context() -> &'static str {
        ED25519_CONTEXT
    }

    fn new_derived(derived: blake3::Hash) -> Self {
        let key = ed25519_dalek::SigningKey::from_bytes(derived.as_bytes());
        Self {key}
    }
 
    fn write_pubkey(&self, dst: &mut [u8]) {
        dst.copy_from_slice(self.key.verifying_key().as_bytes());
    }

    fn sign(self, msg: &[u8], dst: &mut [u8]) {
        let sig = self.key.sign(msg);
        dst.copy_from_slice(&sig.to_bytes());
    }
}

#[derive(Debug)]
pub enum Error {
    MalformedPublicKey,
    MalformedSignature,
    InvalidSignature,
}


fn verify(pubkey: &[u8], sig: &[u8], msg: &[u8]) -> Result<(), Error> {
    if let Ok(pubkey) = ed25519_dalek::VerifyingKey::from_bytes(
        pubkey.try_into().expect("oops"))
    {
        let sig = Signature::from_bytes(sig.try_into().expect("oops"));
        if let Ok(_) = pubkey.verify_strict(msg, &sig) {
            Ok(())
        }
        else {
            Err(Error::InvalidSignature)
        }
    }
    else {
        Err(Error::MalformedPublicKey)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_new() {
        let secret = [7; 32];
        let pair = KeyPair::new(&secret);

        let mut pubkey = [0; 32];
        pair.write_pubkey(&mut pubkey);

        let msg = b"hello all the world, yo!";
        let mut sig = [0; 64];
        pair.sign(msg, &mut sig);
    }
}
