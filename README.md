# ZebraChain 🦓 🔗

[![Build Status](https://github.com/zebrafactory/zebrachain/actions/workflows/rust.yml/badge.svg)](https://github.com/zebrafactory/zebrachain/actions)

ZebraChain is a logged, quantum safe signing protocol designed to replace the long lived asymmetric
key pairs used to sign software releases (and to sign other super important stuff).

## ⚠️ Security Warning

ZebraChain is not yet suitable for production use.

This is a nascent implementation of a yet to be finalized protocol. It's also built on early
(but already awesome) Rust implementations of
[ML-DSA](https://github.com/RustCrypto/signatures/tree/master/ml-dsa) and
[SLH-DSA](https://github.com/RustCrypto/signatures/tree/master/slh-dsa).

## 🦓 Overview

Consider the GPG key used to sign updates for your favorite Linux distribution.  You could replace
it with a ZebraChain, gaining some important benefits over the GPG key:

* Each signature is a new block in a blockchain, with a back-reference to the hash of the previous
block.  This creates a robust, publicly verifiable log of every signature that has be made using a
specific ZebraChain.

* A given asymmetric key pair is only used *once!* Each block contains the signature, the
corresponding public key used to sign the block, and a *forward-reference* to the *hash* of the
corresponding public key that will be used to sign the *next* block. This allows new entropy to be
introduced at each signature, minimizing the problem of whether there was high enough quality
entropy when the ZebraChain was created.

* Entropy accumulation throughout the lifetime of a ZebraChain. At each signature, a new call to
`getrandom()` is made. This new entropy is securely mixed with the current seed (using a keyed
hash), and the result is the next seed.

* Quantum safe. ZebraChain uses the recently standardized
[FIPS 204 ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) quantum secure algorithm in a hybrid
construction with the classically secure [ed25519](https://ed25519.cr.yp.to/) algorithm (as
recommended by the ML-DSA authors). Support for
[FIPS 205 SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final) will be added soon.

The current implementaion has low abstraction and is not configurable, making it easy to review the
protocol. So please jump in and help!

The next step is to make the implemntation configuable for single, double, and tripple hrybrid
signing with ed25519, ML-DSA, and SLH-DSA, supporting all ML-DSA and SLH-DSA parameter sets.

## 🦀 Dependencies of Interest

ZebraChain is built on existing implementations of established cryptographic primitives.

These key crates are used:

* [ed25519-dalek](https://crates.io/crates/ed25519-dalek) and [ml-dsa](https://crates.io/crates/ml-dsa) for hybrid signing.

* [blake3](https://crates.io/crates/blake3) for hashing

* [chacha20poly1305](https://crates.io/crates/chacha20poly1305) for encrypting the secrect blocks

## 🔗 Wire Format

The generic ZebraChain block structure has 8 fields:

```
HASH || SIG || PUB || NEXT_PUB_HASH || PAYLOAD || INDEX || CHAIN_HASH || PREV_HASH
```

Where:

```
HASH = hash(SIG || PUB || NEXT_PUB_HASH || PAYLOAD || INDEX || CHAIN_HASH || PREV_HASH)
```

And where:

```
SIG = sign(PUB || NEXT_PUB_HASH || PAYLOAD || INDEX || CHAIN_HASH || PREV_HASH)
```

The `PUB` field contains both ML-DSA and ed25519 public keys:

```
PUB = (PUB_ML_DSA || PUB_ED25519)
```

And the `SIG` field contains both ML-DSA and ed25519 signatures:

```
SIG = (SIG_ML_DSA || SIG_ED25519)
```

Where:

```
SIG_ED25519 = sign_ed25519(SIGNABLE)
```

And where:

```
SIG_ML_DSA = sign_ml_dsa(SIG_ED25519 || SIGNABLE)
```

The `PAYLOAD` field is the content being signed. Currently it contains a timestamp and a hash,
but it will soon be reworked into a trait, allowing higher level code to define the the size of
palyoad and interpret the payload content however needed.

## 📜 License

The crate is licensed under either of:

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

## 😎 Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
