//! Abstraction over public key signature algorithms.

use crate::block::MutBlock;
use crate::secrets::Seed;
use crate::tunable::*;
use blake3;
use blake3::Hash;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

static ED25519_CONTEXT: &str = "win.zebrachain.sign.ed25519";

fn derive(context: &str, secret: &[u8]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(secret);
    hasher.finalize()
}

/// Abstraction over specific public key algorithms (and hybrid combinations thereof).
///
/// Currently this just signs with ed25519. Soon we will sign using a hybrid
/// Dilithium + ed25519 scheme.
///
/// # Examples
///
/// ```
/// use zebrachain::pksign::KeyPair;
/// let secret = [69u8; 32];
/// let keypair = KeyPair::new(&secret);
/// ```
#[derive(Debug)]
pub struct KeyPair {
    key: SigningKey,
}

impl KeyPair {
    pub fn new(secret: &[u8; 32]) -> Self {
        let h = derive(ED25519_CONTEXT, secret);
        let key = SigningKey::from_bytes(h.as_bytes());
        Self { key }
    }

    /// Write Public Key(s) into buffer (could be ed25519 + Dilithium).
    pub fn write_pubkey(&self, dst: &mut [u8]) {
        dst.copy_from_slice(self.key.verifying_key().as_bytes());
    }

    /// Returns hash of public key byte representation.
    ///
    /// Consumes instance becase we should either make a signature or hash the pubkey, not both.
    pub fn pubkey_hash(self) -> blake3::Hash {
        let mut buf = [0; PUBKEY];
        self.write_pubkey(&mut buf);
        blake3::hash(&buf)
    }

    /// Sign a block being built up.
    ///
    /// Consumes instance because we should only make one signature per KeyPair.
    pub fn sign(self, block: &mut MutBlock) {
        self.write_pubkey(block.as_mut_pubkey());
        let sig = self.key.sign(block.as_signable());
        block.as_mut_signature().copy_from_slice(&sig.to_bytes());
    }
}

pub fn verify_signature(buf: &[u8]) -> bool {
    let bytes: [u8; 32] = buf[PUBKEY_RANGE].try_into().unwrap();
    let sig = Signature::from_bytes(buf[SIGNATURE_RANGE].try_into().unwrap());
    if let Ok(pubkey) = VerifyingKey::from_bytes(&bytes) {
        pubkey.verify_strict(&buf[SIGNABLE_RANGE], &sig).is_ok()
    } else {
        false
    }
}

/// Use to get current KeyPair and next PubKey hash from a Seed.
pub struct SecretSigner {
    keypair: KeyPair,
    next_pubkey_hash: Hash,
}

impl SecretSigner {
    pub fn new(seed: &Seed) -> Self {
        Self {
            keypair: KeyPair::new(seed.secret.as_bytes()),
            next_pubkey_hash: KeyPair::new(seed.next_secret.as_bytes()).pubkey_hash(),
        }
    }
    /*
        The SecretSigner must first copy the pubkey and next_pubkey_hash byte
        representations into the PUBKEY_RANGE and NEXT_PUBKEY_HASH_RANGE, respectively.

        The signature is then computed over the SIGNABLE_RAGE.

        Finally, the byte representation of the signature is copied into
        SIGNATURE_RANGE.

        The SecrectSignner should not compute or set the block hash.
    */

    pub fn sign(self, block: &mut MutBlock) {
        block.set_next_pubkey_hash(&self.next_pubkey_hash);
        self.keypair.sign(block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_dilithium::dilithium3;

    static HEX0: &str = "27ed25c29cfa0c0b5667f9e1bdd6eec1385e815776a4dc8379141da13afa98e1";

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

        let mut buf = vec![0; BLOCK];
        pair.sign(&mut MutBlock::new(&mut buf[..], &Hash::from_bytes([0; 32])));
        assert_eq!(
            buf,
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 216, 233, 52, 240, 118, 99, 178, 28, 218, 52, 185, 250, 51, 196, 35,
                37, 15, 10, 226, 186, 112, 114, 216, 18, 2, 173, 12, 203, 79, 109, 147, 4, 24, 204,
                131, 41, 201, 200, 221, 69, 175, 239, 124, 249, 222, 173, 139, 93, 14, 43, 32, 99,
                19, 58, 151, 62, 220, 33, 42, 156, 63, 104, 37, 1, 54, 112, 220, 24, 105, 66, 248,
                10, 41, 195, 89, 189, 126, 216, 231, 244, 66, 45, 137, 51, 190, 211, 57, 34, 49,
                138, 83, 189, 98, 158, 53, 49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn test_keypair_pubkey_hash() {
        let pair = KeyPair::new(&[69; 32]);
        assert_eq!(pair.pubkey_hash(), blake3::Hash::from_hex(HEX0).unwrap());
    }
}
