//! Hybrid signing and verification with Dilithium + ed25519.

use crate::always::*;
use crate::block::{Block, BlockState, MutBlock, SigningRequest};
use crate::secretseed::{derive, Seed};
use blake3::{hash, Hash};
use ed25519_dalek;
use ml_dsa;
use ml_dsa::{KeyGen, MlDsa65, B32};
use signature::Signer;

fn build_ed25519_keypair(secret: &Hash) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(derive(ED25519_CONTEXT, secret).as_bytes())
}

fn build_dilithium_keypair(secret: &Hash) -> ml_dsa::KeyPair<MlDsa65> {
    let mut hack = B32::default();
    hack.0
        .copy_from_slice(derive(DILITHIUM_CONTEXT, secret).as_bytes()); // FIXME: Do more better
    MlDsa65::key_gen_internal(&hack)
    //pqc_dilithium::Keypair::from_bytes(derive(DILITHIUM_CONTEXT, secret).as_bytes())
}

/*
fn build_sphincsplus_keypair(secret: &Hash) -> pqc_sphincsplus::Keypair {
    let secret = derive(SPHINCSPLUS_CONTEXT, secret);
    pqc_sphincsplus::keypair_from_seed(secret.as_bytes())
}
*/

/// Abstraction over specific public key algorithms (and hybrid combinations thereof).
///
/// Currently this just signs with ed25519. Soon we will sign using a hybrid
/// Dilithium + ed25519 scheme.
///
/// # Examples
///
/// ```
/// let secret = zebrachain::secretseed::random_secret().unwrap();
/// let keypair = zebrachain::pksign::KeyPair::new(&secret);
/// ```
pub struct KeyPair {
    ed25519: ed25519_dalek::SigningKey,
    dilithium: ml_dsa::KeyPair<MlDsa65>,
    //sphincsplus: pqc_sphincsplus::Keypair, // FIXME: We need a seed that is 48 bytes
}

impl KeyPair {
    pub fn new(secret: &Hash) -> Self {
        Self {
            ed25519: build_ed25519_keypair(secret),
            dilithium: build_dilithium_keypair(secret),
        }
    }

    /// Write Public Key(s) into buffer (could be ed25519 + Dilithium).
    pub fn write_pubkey(&self, dst: &mut [u8]) {
        dst[PUB_ED25519_RANGE].copy_from_slice(self.ed25519.verifying_key().as_bytes());
        dst[PUB_DILITHIUM_RANGE].copy_from_slice(self.dilithium.verifying_key.encode().as_slice());
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
        let sig1 = self.ed25519.sign(block.as_signable());
        let sig2 = self
            .dilithium
            .signing_key
            .sign_deterministic(block.as_signable(), b"")
            .unwrap();
        block.as_mut_signature()[SIG_ED25519_RANGE].copy_from_slice(&sig1.to_bytes());
        block.as_mut_signature()[SIG_DILITHIUM_RANGE].copy_from_slice(sig2.encode().as_slice());
    }
}

/// Used to get current KeyPair and next PubKey hash from a Seed.
///
/// # Examples
///
/// ```
/// let seed = zebrachain::secretseed::Seed::auto_create().unwrap();
/// let secsign = zebrachain::pksign::SecretSigner::new(&seed);
/// ```
pub struct SecretSigner {
    keypair: KeyPair,
    next_pubkey_hash: Hash,
}

impl SecretSigner {
    pub fn new(seed: &Seed) -> Self {
        assert_ne!(seed.secret, seed.next_secret);
        Self {
            keypair: KeyPair::new(&seed.secret),
            next_pubkey_hash: KeyPair::new(&seed.next_secret).pubkey_hash(),
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

/// Sign a block buffer.
///
/// Internally, this builds a [MutBlock].
///
/// Honestly, this fn could be the signing API for the whole module. We will see.
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

pub struct Hybrid<'a> {
    block: &'a Block<'a>,
}

impl<'a> Hybrid<'a> {
    fn new(block: &'a Block<'a>) -> Self {
        Self { block }
    }

    fn as_pub_dilithium(&self) -> &[u8] {
        &self.block.as_pubkey()[PUB_DILITHIUM_RANGE]
    }

    fn as_pub_ed25519(&self) -> &[u8] {
        &self.block.as_pubkey()[PUB_ED25519_RANGE]
    }

    fn as_sig_dilithium(&self) -> &[u8] {
        &self.block.as_signature()[SIG_DILITHIUM_RANGE]
    }

    fn as_sig_ed25519(&self) -> &[u8] {
        &self.block.as_signature()[SIG_ED25519_RANGE]
    }

    fn verify_dilithium(&self) -> bool {
        let pubenc =
            ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(self.as_pub_dilithium()).unwrap();
        let pubkey = ml_dsa::VerifyingKey::<MlDsa65>::decode(&pubenc);
        let sigenc =
            ml_dsa::EncodedSignature::<MlDsa65>::try_from(self.as_sig_dilithium()).unwrap();
        if let Some(sig) = ml_dsa::Signature::<MlDsa65>::decode(&sigenc) {
            pubkey.verify_with_context(self.block.as_signable(), b"", &sig)
        } else {
            false
        }
    }

    fn verify_ed25519(&self) -> bool {
        let sigbuf = self.as_sig_ed25519();
        let pubkeybuf = self.as_pub_ed25519();
        let sig = ed25519_dalek::Signature::from_bytes(sigbuf.try_into().unwrap());
        if let Ok(pubkey) = ed25519_dalek::VerifyingKey::from_bytes(pubkeybuf.try_into().unwrap()) {
            pubkey.verify_strict(self.block.as_signable(), &sig).is_ok()
        } else {
            false
        }
    }

    fn verify(&self) -> bool {
        self.verify_ed25519() && self.verify_dilithium()
    }
}

/// Verify the signature of a [Block].
pub fn verify_block_signature(block: &Block) -> bool {
    let hybrid = Hybrid::new(block);
    hybrid.verify()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhelpers::random_request;

    static HEX0: &str = "8e4bb3dfe69f0720a9fc6eb5770c035be4db78a4c127f48691f3c0291711e165";
    static HEX1: &str = "80eb433447f789410ce5261e94880da671cb61140540512c33ba710b43bed605";
    static HEX2: &str = "9a847a51072b98ddaaf55dbae220ef8f13a18a4511165587677d00e9bb19418d";

    #[test]
    fn test_ml_dsa() {
        use ml_dsa::{KeyGen, MlDsa65, B32};
        use signature::{Signer, Verifier};
        let msg = b"This API lets me provide the enropy used to generate the key!";
        let mut secret = B32::default();
        secret.0.copy_from_slice(&[69; 32]);
        let keypair = MlDsa65::key_gen_internal(&secret);
        let sig = keypair.signing_key.sign(msg);
        assert!(keypair.verifying_key.verify(msg, &sig).is_ok());
        assert_eq!(
            keypair.verifying_key.encode().as_slice().len(),
            PUB_DILITHIUM
        );
        assert_eq!(
            hash(keypair.verifying_key.encode().as_slice()),
            Hash::from_hex(HEX1).unwrap()
        );
    }

    #[test]
    fn keypair_new() {
        let secret = Hash::from_bytes([7; 32]);
        let pair = KeyPair::new(&secret);

        let mut pubkey = [0u8; PUBKEY];
        pair.write_pubkey(&mut pubkey);
        assert_eq!(hash(&pubkey), Hash::from_hex(HEX2).unwrap());
    }

    #[test]
    fn test_keypair_pubkey_hash() {
        let pair = KeyPair::new(&Hash::from_bytes([69; 32]));
        assert_eq!(pair.pubkey_hash(), Hash::from_hex(HEX0).unwrap());
    }

    #[test]
    fn test_sign_block() {
        // Sign first block
        let mut buf = [69; BLOCK]; // 69 to make sure block gets zeroed first
        let seed = Seed::auto_create().unwrap();
        let request = random_request();
        let chain_hash = sign_block(&mut buf, &seed, &request, None);

        // chain_hash and previous_hash are always zeros in 1st block:
        assert_eq!(&buf[0..DIGEST], chain_hash.as_bytes());
        assert_eq!(&buf[BLOCK - DIGEST * 2..], &[0; DIGEST * 2]);

        // Sign 2nd block
        let tail = Block::from_hash_at_index(&buf, &chain_hash, 0)
            .unwrap()
            .state();
        buf.fill(69);
        let seed = seed.auto_advance().unwrap();
        let request = random_request();
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
        let tail2 = Block::from_hash_at_index(&buf, &block_hash, 1)
            .unwrap()
            .state();
        buf.fill(69);
        let seed = seed.auto_advance().unwrap();
        let request = random_request();
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

    #[test]
    #[should_panic]
    fn test_sign_block_panic() {
        // Sign first block
        let mut buf = [0; BLOCK];
        let seed = Seed::auto_create().unwrap();
        let request = random_request();
        let chain_hash = sign_block(&mut buf, &seed, &request, None);

        // Sign 2nd block, but double advance the seed:
        let tail = Block::from_hash_at_index(&buf, &chain_hash, 0)
            .unwrap()
            .state();
        let seed = seed.auto_advance().unwrap().auto_advance().unwrap();
        let request = random_request();
        let _block_hash = sign_block(&mut buf, &seed, &request, Some(&tail));
    }
}
