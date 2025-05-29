//! Hybrid signing and verification with ML-DSA + ed25519.

use crate::always::*;
use crate::block::{Block, MutBlock};
use crate::hashing::{Hash, Secret, derive_secret};
use crate::secretseed::Seed;
use ml_dsa::{B32, KeyGen, MlDsa65};
use signature::Signer;
use zeroize::Zeroize;

fn build_ed25519_keypair(secret: &Secret) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(derive_secret(CONTEXT_ED25519, secret).as_bytes())
}

fn build_mldsa_keypair(secret: &Secret) -> ml_dsa::KeyPair<MlDsa65> {
    let mut hack = B32::default();
    hack.0
        .copy_from_slice(derive_secret(CONTEXT_ML_DSA, secret).as_bytes()); // FIXME: Do more better
    MlDsa65::key_gen_internal(&hack)
}

struct KeyPair {
    ed25519: ed25519_dalek::SigningKey,
    mldsa: ml_dsa::KeyPair<MlDsa65>,
}

impl KeyPair {
    fn new(secret: &Secret) -> Self {
        Self {
            ed25519: build_ed25519_keypair(secret),
            mldsa: build_mldsa_keypair(secret),
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
    /// Consumes instance becase we should either make a signature or hash the pubkey, not both.
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
    pub(crate) fn new(seed: &Seed) -> Self {
        assert_ne!(seed.secret, seed.next_secret);
        Self {
            keypair: KeyPair::new(&seed.secret),
            next_pubkey_hash: KeyPair::new(&seed.next_secret).pubkey_hash(),
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
        let pubenc = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(self.as_pub_mldsa()).unwrap();
        let pubkey = ml_dsa::VerifyingKey::<MlDsa65>::decode(&pubenc);
        let sigenc = ml_dsa::EncodedSignature::<MlDsa65>::try_from(self.as_sig_mldsa()).unwrap();
        if let Some(sig) = ml_dsa::Signature::<MlDsa65>::decode(&sigenc) {
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

    static HEX0: &str = "8e4bb3dfe69f0720a9fc6eb5770c035be4db78a4c127f48691f3c0291711e165";
    static HEX1: &str = "80eb433447f789410ce5261e94880da671cb61140540512c33ba710b43bed605";
    static HEX2: &str = "9a847a51072b98ddaaf55dbae220ef8f13a18a4511165587677d00e9bb19418d";

    fn build_mldsa_test(secret: &Secret) -> ml_dsa::KeyPair<MlDsa65> {
        // Does not use a derived secret, don't use for realsies!
        let mut hack = B32::default();
        hack.0.copy_from_slice(secret.as_bytes()); // FIXME: Do more better
        MlDsa65::key_gen_internal(&hack)
    }

    #[test]
    fn test_ml_dsa() {
        use ml_dsa::{B32, KeyGen, MlDsa65};
        use signature::{Signer, Verifier};
        let msg = b"This API lets me provide the enropy used to generate the key!";
        let mut secret = B32::default();
        secret.0.copy_from_slice(&[69; 32]);
        let keypair = MlDsa65::key_gen_internal(&secret);
        let sig = keypair.signing_key().sign(msg);
        assert!(keypair.verifying_key().verify(msg, &sig).is_ok());
        assert_eq!(keypair.verifying_key().encode().as_slice().len(), PUB_MLDSA);
        assert_eq!(
            Hash::compute(keypair.verifying_key().encode().as_slice()),
            Hash::from_hex(HEX1).unwrap()
        );
    }

    #[test]
    fn test_build_ed25519_keypair() {
        // Make sure a derived secret is used and not the parent secret directly
        let secret = Secret::from_bytes([69; DIGEST]);
        let derived_secret = derive_secret(CONTEXT_ED25519, &secret);
        let bad = ed25519_dalek::SigningKey::from_bytes(secret.as_bytes());
        let good = ed25519_dalek::SigningKey::from_bytes(derived_secret.as_bytes());
        let ret = build_ed25519_keypair(&secret);
        assert_ne!(
            ret.verifying_key().as_bytes(),
            bad.verifying_key().as_bytes()
        );
        assert_eq!(
            ret.verifying_key().as_bytes(),
            good.verifying_key().as_bytes()
        );
    }

    #[test]
    fn test_build_mldsa_keypair() {
        // Make sure a derived secret is used and not the parent secret directly
        let secret = Secret::from_bytes([69; DIGEST]);
        let derived_secret = derive_secret(CONTEXT_ML_DSA, &secret);
        let bad = build_mldsa_test(&secret);
        let good = build_mldsa_test(&derived_secret);
        let ret = build_mldsa_keypair(&secret);
        assert_ne!(
            ret.verifying_key().encode().as_slice(),
            bad.verifying_key().encode().as_slice()
        );
        assert_eq!(
            ret.verifying_key().encode().as_slice(),
            good.verifying_key().encode().as_slice()
        );
    }

    #[test]
    fn keypair_new() {
        let secret = Secret::from_bytes([7; 32]);
        let pair = KeyPair::new(&secret);

        let mut pubkey = [0u8; PUBKEY];
        pair.write_pubkey(&mut pubkey);
        assert_eq!(Hash::compute(&pubkey), Hash::from_hex(HEX2).unwrap());
    }

    #[test]
    fn test_keypair_pubkey_hash() {
        let pair = KeyPair::new(&Secret::from_bytes([69; 32]));
        assert_eq!(pair.pubkey_hash(), Hash::from_hex(HEX0).unwrap());
    }
}
