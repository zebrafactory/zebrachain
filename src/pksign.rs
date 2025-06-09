//! Hybrid signing and verification with ML-DSA + ed25519.

use crate::always::*;
use crate::{Block, Hash, MutBlock, Secret, Seed, SubSecret256};
use ml_dsa::{B32, KeyGen, MlDsa44};
use signature::Signer;
use zeroize::Zeroize;

fn build_ed25519_keypair(secret: SubSecret256) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(secret.as_bytes())
}

fn build_mldsa_keypair(secret: SubSecret256) -> ml_dsa::KeyPair<MlDsa44> {
    let mut hack = B32::default();
    hack.0.copy_from_slice(secret.as_bytes()); // FIXME: Do more better
    MlDsa44::key_gen_internal(&hack)
}

struct KeyPair {
    ed25519: ed25519_dalek::SigningKey,
    mldsa: ml_dsa::KeyPair<MlDsa44>,
}

impl KeyPair {
    fn new(secret: &Secret, block_index: u128) -> Self {
        // Why use the block index as salt when deriving the keys? Say something went horribly
        // wrong and somehow every single block in the chain was signed with the same Secret.
        // Well, using the index as salt means that each block-wise position in the chain would
        // still be signed with different ed25519 and ML-DSA keys. So as long as this improperly
        // reused Secret is unknown to attackers, ZebraChain still has the security properties we
        // want.
        //
        // Defense in depth, yo. Also, a central design theme in ZebraChain is, "Don't reuse shit,
        // ever".
        let key1 = secret.derive_sub_secret_256(block_index, CONTEXT_ED25519);
        let key2 = secret.derive_sub_secret_256(block_index, CONTEXT_ML_DSA);
        assert_ne!(key1, key2); // Does constant time compare
        Self {
            ed25519: build_ed25519_keypair(key1),
            mldsa: build_mldsa_keypair(key2),
        }
    }

    /// Write Public Keys into buffer (both ed25519 and ML-DSA).
    fn write_pubkey(&self, dst: &mut [u8]) {
        assert_eq!(dst.len(), PUBKEY);
        dst[PUB_ED25519_RANGE].copy_from_slice(self.ed25519.verifying_key().as_bytes());
        dst[PUB_MLDSA_RANGE].copy_from_slice(self.mldsa.verifying_key().encode().as_slice());
    }

    /// Returns hash of public key byte representation.
    ///
    /// Consumes instance because we should either make a signature or hash the pubkey, not both.
    fn pubkey_hash(self) -> Hash {
        let mut buf = [0; PUBKEY];
        self.write_pubkey(&mut buf);
        let pubkey_hash = Hash::compute(&buf);
        buf.zeroize(); // We treat the next public key as secret till use, so zeroize buf
        pubkey_hash
    }

    /// Sign a block being built up.
    ///
    /// Consumes instance because we should only make one signature per KeyPair.
    fn sign(self, block: &mut MutBlock) {
        // Write pubkey to buffer because we sign that:
        self.write_pubkey(block.as_mut_pubkey());

        // Compute ed25519 signature. Then write it to the buffer because ML-DSA signs the
        // the ed25519 signature plus the rest of the block (SIGNABLE2_RANGE):
        let sig = self.ed25519.sign(block.as_signable());
        block.as_mut_signature()[SIG_ED25519_RANGE].copy_from_slice(&sig.to_bytes());

        // Compute ML-DSA signature over SIGNABLE2_RANGE, then write it to the buffer:
        let sig = self
            .mldsa
            .signing_key()
            .sign_deterministic(block.as_signable2(), SIGNING_CXT_ML_DSA)
            .unwrap();
        block.as_mut_signature()[SIG_MLDSA_RANGE].copy_from_slice(sig.encode().as_slice());
    }
}

pub(crate) struct SecretSigner {
    keypair: KeyPair,
    next_pubkey_hash: Hash,
}

impl SecretSigner {
    pub(crate) fn new(seed: &Seed, index: u128) -> Self {
        assert_ne!(seed.secret, seed.next_secret);
        Self {
            keypair: KeyPair::new(&seed.secret, index),
            next_pubkey_hash: KeyPair::new(&seed.next_secret, index + 1).pubkey_hash(),
        }
    }

    /// Sign a [MutBlock].
    pub(crate) fn sign(self, block: &mut MutBlock) {
        // First write next_pubkey_hash because that's part of what we sign:
        block.set_next_pubkey_hash(&self.next_pubkey_hash);
        self.keypair.sign(block);
    }
}

struct Hybrid<'a> {
    block: &'a Block<'a>,
}

impl<'a> Hybrid<'a> {
    fn new(block: &'a Block<'a>) -> Self {
        Self { block }
    }

    fn as_pub_mldsa(&self) -> &[u8] {
        &self.block.as_pubkey()[PUB_MLDSA_RANGE]
    }

    fn as_pub_ed25519(&self) -> &[u8] {
        &self.block.as_pubkey()[PUB_ED25519_RANGE]
    }

    fn as_sig_mldsa(&self) -> &[u8] {
        &self.block.as_signature()[SIG_MLDSA_RANGE]
    }

    fn as_sig_ed25519(&self) -> &[u8] {
        &self.block.as_signature()[SIG_ED25519_RANGE]
    }

    fn verify_mldsa(&self) -> bool {
        let pubenc = ml_dsa::EncodedVerifyingKey::<MlDsa44>::try_from(self.as_pub_mldsa()).unwrap();
        let pubkey = ml_dsa::VerifyingKey::<MlDsa44>::decode(&pubenc);
        let sigenc = ml_dsa::EncodedSignature::<MlDsa44>::try_from(self.as_sig_mldsa()).unwrap();
        if let Some(sig) = ml_dsa::Signature::<MlDsa44>::decode(&sigenc) {
            pubkey.verify_with_context(self.block.as_signable2(), SIGNING_CXT_ML_DSA, &sig)
        } else {
            false
        }
    }

    fn verify_ed25519(&self) -> bool {
        let sigbuf = self.as_sig_ed25519();
        let pubkeybuf = self.as_pub_ed25519();
        let sig = ed25519_dalek::Signature::from_bytes(sigbuf.try_into().unwrap());
        match ed25519_dalek::VerifyingKey::from_bytes(pubkeybuf.try_into().unwrap()) {
            Ok(pubkey) => pubkey.verify_strict(self.block.as_signable(), &sig).is_ok(),
            _ => false,
        }
    }

    fn verify(&self) -> bool {
        self.verify_ed25519() && self.verify_mldsa()
    }
}

/// Verify the signature of a [Block].
pub(crate) fn verify_block_signature(block: &Block) -> bool {
    let hybrid = Hybrid::new(block);
    hybrid.verify()
}

#[cfg(test)]
mod tests {
    use super::*;

    static HEX0: &str =
        "91fe0289ef25b99560858c4405f984d0c776d4bc9f761327c381ab709316dff3e66d9dd2af882d47";
    //static HEX1: &str =
    //    "d7c58110f5c997d2a4439c47d0212eca4f8f26236605841b44417a74fcacdbca034d3d2d1e64d019";
    static HEX2: &str =
        "10e651d0df11d8980e51d7c2462751627148faf391e0c74be40bb364e8ba970a074602f552ba2477";

    // FIXME: Add new tests for ml-dsa and ed25519 keypair generation, but API needs rework first

    #[test]
    fn keypair_new() {
        let secret = Secret::from_bytes([7; SECRET]);
        let pair = KeyPair::new(&secret, 0);

        let mut pubkey = [0u8; PUBKEY];
        pair.write_pubkey(&mut pubkey);
        assert_eq!(Hash::compute(&pubkey), Hash::from_hex(HEX2).unwrap());
    }

    #[test]
    fn test_keypair_pubkey_hash() {
        let pair = KeyPair::new(&Secret::from_bytes([69; SECRET]), 0);
        assert_eq!(pair.pubkey_hash(), Hash::from_hex(HEX0).unwrap());
    }
}
