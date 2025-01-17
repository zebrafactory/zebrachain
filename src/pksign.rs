//! Abstraction over public key signature algorithms.

use crate::always::*;
use crate::block::{Block, BlockState, MutBlock, SigningRequest};
use crate::secretseed::{derive, Seed};
use blake3::{hash, Hash};
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
    pub fn pubkey_hash(self) -> Hash {
        let mut buf = [0; PUBKEY];
        self.write_pubkey(&mut buf);
        hash(&buf)
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

/// Used to get current KeyPair and next PubKey hash from a Seed.
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

pub fn sign_block(
    buf: &mut [u8],
    seed: &Seed,
    request: &SigningRequest,
    last: Option<&BlockState>,
) -> Hash {
    let mut block = MutBlock::new(buf, request);
    if let Some(last) = last {
        block.set_previous(last);
    }
    let secsign = SecretSigner::new(seed);
    secsign.sign(&mut block);
    if let Some(last) = last {
        assert_eq!(last.next_pubkey_hash, block.compute_pubkey_hash());
    }
    block.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secretseed::random_hash;
    use pqc_dilithium;
    use pqcrypto_dilithium;

    static HEX0: &str = "450f17b763621657bf0757a314a2162107a4e526950ca22785dc9fdeb0e5ac69";

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
        let request = SigningRequest::new(Hash::from_bytes([0; 32]), Hash::from_bytes([0; 32]));
        pair.sign(&mut MutBlock::new(&mut buf[..], &request));
        assert_eq!(
            buf,
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 26, 101, 75, 144, 196, 207, 177, 103, 157, 142, 137, 28, 191, 246, 239,
                230, 244, 104, 160, 73, 101, 225, 127, 58, 168, 154, 96, 132, 196, 16, 254, 145,
                188, 187, 45, 183, 113, 17, 203, 20, 179, 80, 52, 231, 113, 63, 237, 3, 46, 190,
                84, 69, 98, 143, 248, 102, 44, 166, 72, 208, 46, 0, 195, 8, 170, 86, 112, 232, 142,
                253, 215, 96, 247, 143, 14, 222, 203, 77, 215, 154, 16, 16, 99, 205, 43, 163, 110,
                109, 212, 55, 23, 31, 70, 54, 253, 71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn test_keypair_pubkey_hash() {
        let pair = KeyPair::new(&[69; 32]);
        assert_eq!(pair.pubkey_hash(), Hash::from_hex(HEX0).unwrap());
    }

    #[test]
    fn test_sign_block() {
        // Sign first block
        let mut buf = [69; BLOCK]; // 69 to make sure block gets zeroed first
        let seed = Seed::auto_create();
        let request = SigningRequest::new(random_hash(), random_hash());
        let chain_hash = sign_block(&mut buf, &seed, &request, None);
        assert_eq!(&buf[0..DIGEST], chain_hash.as_bytes());
        assert_eq!(&buf[BLOCK - DIGEST * 2..], &[0; DIGEST * 2]); // previous_hash, chain_hash == 0

        // Sign 2nd block
        let tail = Block::from_hash(&buf, &chain_hash).unwrap().state();
        buf.fill(69);
        let seed = seed.auto_advance();
        let request = SigningRequest::new(random_hash(), random_hash());
        let block_hash = sign_block(&mut buf, &seed, &request, Some(&tail));
        assert_ne!(chain_hash, block_hash);
        assert_eq!(&buf[0..DIGEST], block_hash.as_bytes());
        // chain_hash and previous_hash are always == in the 2nd block:
        assert_eq!(&buf[BLOCK - DIGEST..], chain_hash.as_bytes());
        assert_eq!(
            &buf[BLOCK - DIGEST * 2..BLOCK - DIGEST],
            chain_hash.as_bytes()
        );

        // Sign 3rd block
        let tail2 = Block::from_hash(&buf, &block_hash).unwrap().state();
        buf.fill(69);
        let seed = seed.auto_advance(); //.auto_advance(); // <-- Will break
        let request = SigningRequest::new(random_hash(), random_hash());
        let block2_hash = sign_block(&mut buf, &seed, &request, Some(&tail2));
        assert_ne!(block_hash, block2_hash);
        assert_ne!(chain_hash, block2_hash);
        assert_eq!(&buf[0..DIGEST], block2_hash.as_bytes());
        assert_eq!(&buf[BLOCK - DIGEST..], chain_hash.as_bytes());
        assert_eq!(
            &buf[BLOCK - DIGEST * 2..BLOCK - DIGEST],
            block_hash.as_bytes()
        );
    }
}
