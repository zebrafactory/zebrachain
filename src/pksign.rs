//! Abstraction over public key signature algorithms.

use crate::always::*;
use crate::block::{Block, BlockState, MutBlock};
use crate::secretseed::{derive, Seed};
use blake3;
use blake3::Hash;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

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
        let h1 = derive(ED25519_CONTEXT, secret);
        let _h2 = derive(DILITHIUM_CONTEXT, secret); // Once doing hybrid singing
        let key = SigningKey::from_bytes(h1.as_bytes());
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

pub fn verify_signature(block: &Block) -> bool {
    let sig = Signature::from_bytes(block.as_signature().try_into().unwrap());
    if let Ok(pubkey) = VerifyingKey::from_bytes(block.as_pubkey().try_into().unwrap()) {
        pubkey.verify_strict(block.as_signable(), &sig).is_ok()
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

        The SecrectSigner should not compute or set the block hash.
    */

    pub fn sign(self, block: &mut MutBlock) {
        block.set_next_pubkey_hash(&self.next_pubkey_hash);
        self.keypair.sign(block);
    }
}

pub fn sign_block<'a>(
    buf: &'a mut [u8],
    seed: &Seed,
    state_hash: &Hash,
    last: Option<&BlockState>,
) -> Block<'a> {
    let mut block = MutBlock::new(buf, state_hash);
    if let Some(last) = last {
        block.set_previous(last);
    }
    let secsign = SecretSigner::new(seed);
    secsign.sign(&mut block);
    let block_hash = block.finalize();
    Block::from_hash(buf, &block_hash).unwrap()
}

pub fn sign_first_block<'a>(buf: &'a mut [u8], seed: &Seed, state_hash: &Hash) -> Block<'a> {
    sign_block(buf, seed, state_hash, None)
}

pub fn sign_next_block<'a>(
    buf: &'a mut [u8],
    seed: &Seed,
    state_hash: &Hash,
    last: &BlockState,
) -> Block<'a> {
    sign_block(buf, seed, state_hash, Some(last))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqc_dilithium;
    use pqcrypto_dilithium;

    static HEX0: &str = "450f17b763621657bf0757a314a2162107a4e526950ca22785dc9fdeb0e5ac69";

    fn dummy_block_state() -> BlockState {
        BlockState {
            counter: 0,
            block_hash: Hash::from_bytes([1; DIGEST]),
            chain_hash: Hash::from_bytes([2; DIGEST]),
            next_pubkey_hash: Hash::from_bytes([3; DIGEST]),
        }
    }

    #[test]
    fn test_pqcrypto_dilithium() {
        let msg = b"Wish this API let me provide the entropy used to generate the key";
        let (pk, sk) = pqcrypto_dilithium::dilithium3::keypair();
        let sm = pqcrypto_dilithium::dilithium3::sign(msg, &sk);
        let vmsg = pqcrypto_dilithium::dilithium3::open(&sm, &pk).unwrap();
        assert_eq!(vmsg, msg);
    }

    #[test]
    fn test_pqc_dilithium() {
        let msg = b"Wish this API let me provide the entropy used to generate the key";
        let kp = pqc_dilithium::Keypair::generate();
        let sig = kp.sign(msg);
        assert!(pqc_dilithium::verify(&sig, msg, &kp.public).is_ok());
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
                170, 86, 112, 232, 142, 253, 215, 96, 247, 143, 14, 222, 203, 77, 215, 154, 16, 16,
                99, 205, 43, 163, 110, 109, 212, 55, 23, 31, 70, 54, 253, 71
            ]
        );

        let mut buf = vec![0; BLOCK];
        pair.sign(&mut MutBlock::new(&mut buf[..], &Hash::from_bytes([0; 32])));
        assert_eq!(
            buf,
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 23, 177, 172, 5, 87, 69, 180, 219, 115, 118, 73, 22, 159, 138, 88, 111,
                140, 155, 133, 202, 136, 146, 9, 170, 235, 201, 77, 13, 144, 35, 236, 21, 68, 45,
                141, 116, 245, 41, 83, 213, 117, 103, 53, 90, 111, 19, 225, 72, 231, 165, 2, 12,
                104, 142, 113, 100, 191, 104, 15, 165, 182, 245, 123, 14, 170, 86, 112, 232, 142,
                253, 215, 96, 247, 143, 14, 222, 203, 77, 215, 154, 16, 16, 99, 205, 43, 163, 110,
                109, 212, 55, 23, 31, 70, 54, 253, 71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0
            ]
        );
    }

    #[test]
    fn test_keypair_pubkey_hash() {
        let pair = KeyPair::new(&[69; 32]);
        assert_eq!(pair.pubkey_hash(), blake3::Hash::from_hex(HEX0).unwrap());
    }
}
