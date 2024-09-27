//! Abstraction over public key signature algorithms.

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
    outside the Pair.  We do need to expose the public key bytes to the outside,
    though.

4.  Generate the

*/

/// Trait to expose the needed bits of a (secret, private) keypair.
///
/// Remember that a `Pair` could be a Dilithium + ed25519 hybrid pair.
pub trait Pair {
    /// We need deterministic Pair generation from the same secret.
    ///
    /// This should work from an arbitrary secret and 
    fn new(secret: &[u8]) -> impl Pair;

    /// Write public key into byte slice.
    fn write_pubkey(&self, dst: &mut [u8]);

    /// Sign message.
    fn sign(self, msg: &[u8], dst: &mut [u8]);
}


struct Hybrid {
    buf: Vec<u8>,
}

impl Pair for Hybrid {
    fn new(_secret: &[u8]) -> Hybrid {
        Hybrid {buf: Vec::new()}
    }
 
    fn write_pubkey(&self, dst: &mut [u8]) {
    }

    fn sign(self, msg: &[u8], dst: &mut [u8]) {
        ()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail() {
        assert!(false);
    }
}