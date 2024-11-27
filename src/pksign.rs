//! Abstraction over public key signature algorithms.

use blake3;
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey};

static ED25519_CONTEXT: &str = "win.zebrachain.sign.ed25519";

fn derive(context: &str, secret: &[u8]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(secret);
    hasher.finalize()
}

#[derive(Debug)]
pub struct KeyPair {
    key: ed25519_dalek::SigningKey,
}

impl KeyPair {
    pub fn new(secret: &[u8]) -> Self {
        let h = derive(ED25519_CONTEXT, secret);
        let key = ed25519_dalek::SigningKey::from_bytes(h.as_bytes());
        Self { key }
    }

    pub fn write_pubkey(&self, dst: &mut [u8]) {
        dst.copy_from_slice(self.key.verifying_key().as_bytes());
    }

    // Consumes instance because we should only make one signature per KeyPair1
    pub fn sign(self, msg: &[u8], dst: &mut [u8]) {
        let sig = self.key.sign(msg);
        dst.copy_from_slice(&sig.to_bytes());
    }

    // Consumes instance because we should only make one signature per KeyPair1
    pub fn sign2(self, msg: &[u8]) -> [u8; 64] {
        let sig = self.key.sign(msg);
        sig.to_bytes()
    }
}

#[derive(Debug)]
pub enum Error {
    MalformedPublicKey,
    MalformedSignature,
    InvalidSignature,
}

fn verify(pubkey: &[u8], sig: &[u8], msg: &[u8]) -> Result<(), Error> {
    if let Ok(pubkey) = ed25519_dalek::VerifyingKey::from_bytes(pubkey.try_into().expect("oops")) {
        let sig = Signature::from_bytes(sig.try_into().expect("oops"));
        if let Ok(_) = pubkey.verify_strict(msg, &sig) {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    } else {
        Err(Error::MalformedPublicKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_dilithium::dilithium3;

    #[test]
    fn test_dilithium() {
        // FIXME: We need an API that allows us to generate from a seed
        let msg = b"hello";
        let (pk, sk) = dilithium3::keypair();
        let sm = dilithium3::sign(msg, &sk);
        let vmsg = dilithium3::open(&sm, &pk).unwrap();
        assert_eq!(vmsg, msg);
    }

    #[test]
    fn derive_key() {
        let secret = [7; 32];

        let h = derive("example0", &secret);
        assert_eq!(
            h.as_bytes(),
            &[
                201, 197, 207, 85, 251, 50, 175, 230, 93, 166, 135, 151, 254, 182, 137, 72, 247,
                158, 154, 71, 13, 107, 98, 185, 50, 220, 200, 223, 244, 224, 121, 36
            ]
        );

        let h = derive("example1", &secret);
        assert_eq!(
            h.as_bytes(),
            &[
                12, 255, 43, 240, 22, 55, 198, 18, 190, 243, 159, 226, 207, 193, 9, 243, 40, 12,
                148, 123, 160, 138, 63, 163, 136, 72, 203, 47, 243, 111, 81, 122
            ]
        );

        let secret = [8; 32];

        let h = derive("example0", &secret);
        assert_eq!(
            h.as_bytes(),
            &[
                85, 20, 18, 22, 96, 47, 74, 31, 16, 135, 2, 135, 147, 82, 64, 78, 92, 122, 8, 72,
                237, 33, 68, 119, 115, 195, 18, 171, 140, 184, 186, 101
            ]
        );

        let h = derive("example1", &secret);
        assert_eq!(
            h.as_bytes(),
            &[
                168, 183, 42, 224, 55, 249, 54, 53, 86, 216, 99, 36, 116, 156, 36, 118, 92, 240,
                132, 61, 243, 141, 196, 154, 196, 167, 54, 161, 134, 248, 4, 201
            ]
        );
    }

    #[test]
    fn keypair_new() {
        let secret = [7; 32];
        let pair = KeyPair::new(&secret);

        let mut pubkey = [0u8; 32];
        pair.write_pubkey(&mut pubkey);
        assert_eq!(
            pubkey,
            [
                54, 112, 220, 24, 105, 66, 248, 10, 41, 195, 89, 189, 126, 216, 231, 244, 66, 45,
                137, 51, 190, 211, 57, 34, 49, 138, 83, 189, 98, 158, 53, 49
            ]
        );

        let msg = b"hello all the world, yo!";
        let mut sig = [0u8; 64];
        pair.sign(msg, &mut sig);
        assert_eq!(
            sig,
            [
                49, 206, 153, 167, 46, 196, 137, 170, 211, 11, 118, 171, 219, 141, 177, 220, 167,
                186, 248, 227, 236, 191, 24, 158, 120, 191, 213, 150, 71, 193, 250, 224, 64, 162,
                240, 212, 89, 58, 116, 193, 12, 158, 0, 67, 200, 235, 219, 94, 101, 46, 55, 133,
                123, 57, 88, 39, 102, 63, 227, 26, 186, 138, 85, 9
            ]
        );
    }
}
