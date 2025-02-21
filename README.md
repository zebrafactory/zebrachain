# ZebraChain 🦓 🔗

[![Build Status](https://github.com/zebrafactory/zebrachain/actions/workflows/rust.yml/badge.svg)](https://github.com/zebrafactory/zebrachain/actions)

ZebraChain is a logged, quantum safe signing protocol designed to replace the long lived asymmetric
key pairs used to sign software releases (and to sign other super important stuff).

## ⚠️ Security Warning

ZebraChain is not yet suitable for production use.

This is a nascent implementation of a yet to be finalized protocol. It's also built on a nascent
(but already awesome)
[Rust implementation of ML-DSA](https://github.com/RustCrypto/signatures/tree/master/ml-dsa).

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
`getrandom()` is made. This new entropy is securely mixed with the current seed (using a keyed hash), and the result is the next seed.

* Quantum safe. ZebraChain uses the recently standardizied
[ML-DSA FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) quantum secure algorithm in a hybrid
construction with the classically secure [ed25519](https://ed25519.cr.yp.to/) algorithm (as
recommended by the ML-DSA authors). Support for
[SLH-DSA FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) will be added soon.

* *Some* quantum mitigation, even if ML-DSA is broken.  A sufficiently large quantum computer can
get the secret key from an ed25519 public key (that's the whole problem).  But that same quantum
computer *cannot* get the ed25519 public key from the *hash* of that public key. So if consumers of
the chain locally checkpoint the hash of the latest block, a quantum attack cannot be attempted
until the owner of the ZebraChain publishes their next valid signature block (after which the public
key for the block is exposed, allowing a quantum attacker to get the secret key and forge arbitrary
signatures for that position in the chain).

## 🦀 Dependencies of Interest

ZebraChain is built on existing implementations of established cryptographic primatives.

These key crates are used:

* [ed25519-dalek](https://crates.io/crates/ed25519-dalek) and [ml-dsa](https://crates.io/crates/ml-dsa) for hybrid signing.

* [blake3](https://crates.io/crates/blake3) for hashing

* [chacha20poly1305](https://crates.io/crates/chacha20poly1305) for encrypting the secrect blocks

* [getrandom](https://crates.io/crates/getrandom) for accessing the operating system CSPRNG


## 🔗 Wire Format

A ZebraChain block currently has 10 fields:

```
HASH || SIG || PUB || NEXT_PUB_HASH || TIME || AUTH_HASH || STATE_HASH || INDEX || PREV_HASH || CHAIN_HASH
```

Where:

```
HASH = hash(SIG || PUB || NEXT_PUB_HASH || TIME || AUTH_HASH || STATE_HASH || INDEX || PREV_HASH || CHAIN_HASH)
```

And where:

```
SIG = sign(PUB || NEXT_PUB_HASH || TIME || AUTH_HASH || STATE_HASH || INDEX || PREV_HASH || CHAIN_HASH)
```

The `PUB` field expands into:

```
PUB = (PUB_ML_DSA || PUB_ED25519)
```

And the `SIG` field expands into:

```
SIG = (SIG_ML_DSA || SIG_ED25519)
```

## 📜 License

The crate is licensed under either of:

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

## 😎 Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
