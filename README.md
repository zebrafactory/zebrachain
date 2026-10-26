# 🦓 🔗 ZebraChain

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status](https://github.com/zebrafactory/zebrachain/actions/workflows/rust.yml/badge.svg)](https://github.com/zebrafactory/zebrachain/actions)

ZebraChain is a logged, quantum safe signing protocol designed to replace the long lived asymmetric
key pairs used to sign software releases (and to sign other super important stuff).

In short, ZebraChain:

* Logs each signature in a block chain

* Is quantum secure because it uses ML-DSA + ed25519 in a hybrid signing construction

* Changes the keypairs at every signature by including the public key used to sign the current
block and the hash of the public key that will be used to sign the next block

This is a pre-release crate. The API is still being finalized. The 0.0.x releases make no API commitments, nor any
commits to the protocol.

However, the dust is settling quickly and it's a perfect time to jump in and start building
experimental applications on top of ZebraChain! If you are interested, please jump in and help!
Feedback and pull requests welcome!

See the [Quickstart](https://docs.rs/zf-zebrachain/latest/zf_zebrachain/#-quickstart) for an overview of the API.

## ⚠️ Security Warning

ZebraChain is not yet suitable for production use. This is a nascent implementation of a yet to be
finalized protocol.

## 🦓 Overview

Consider the GPG key used to sign updates for your favorite Linux distribution.  You could replace
it with a ZebraChain, gaining some important benefits over the GPG key:

* Each signature is a new block in a blockchain, with a back-reference (the hash of the previous
block).  This creates a robust, publicly verifiable log of every signature that has be made using a
specific ZebraChain.

* A given asymmetric key pair is only used *once!* Each block contains the signature, the
corresponding public key used to sign the block, and a *forward-reference* (the *hash* of the
corresponding public key that will be used to sign the *next* block).

* Entropy accumulation throughout the lifetime of a ZebraChain. At each signature, a new call to
`getrandom()` is made. This new entropy is securely mixed with the current seed (using a keyed
hash), and the result is the next seed. This allows new entropy to be introduced at each signature,
minimizing the problem of whether there was high enough quality entropy when the ZebraChain was created.

* Quantum safe. ZebraChain uses the
[FIPS 204 ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) quantum secure algorithm in a hybrid
construction with the classically secure [ed25519](https://ed25519.cr.yp.to/) algorithm (as
recommended by the ML-DSA authors).

## 🦀 Dependencies of Interest

ZebraChain is built on existing implementations of established cryptographic primitives.

These key crates are used:

* [ed25519-dalek](https://crates.io/crates/ed25519-dalek) and [ml-dsa](https://crates.io/crates/ml-dsa) for hybrid signing.

* [blake2](https://crates.io/crates/blake2) for hashing and KDF.

* [chacha20poly1305](https://crates.io/crates/chacha20poly1305) for encrypting and authenticating the secret blocks.

* [argon2](https://crates.io/crates/argon2) for PBKDF.

## 🔗 Wire Format

A ZebraChain block has 8 fields:

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
PUB = PUB_ML_DSA || PUB_ED25519
```

And the `SIG` field contains both ML-DSA and ed25519 signatures:

```
SIG = SIG_ML_DSA || SIG_ED25519
```

Where:

```
SIG_ED25519 = sign_ed25519(SIGNABLE)
```

And where:

```
SIG_ML_DSA = sign_ml_dsa(SIG_ED25519 || SIGNABLE)
```

(Note that ML-DSA signs both the ed22519 signature and the signable portion of the block.)

The `PAYLOAD` field is the content being signed. Currently it contains a timestamp and a hash,
but it will soon be reworked into a trait, allowing higher level code to define the the size of
the payload and interpret the payload content however needed.

## 📜 License

The crate is licensed under either of:

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

## 🧑‍🏭 Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

## 🤖 AI/LLM Contribution Policy

An open source software project thrives best when a large number of human brains have a deep,
ongoing, and evolving understanding of the project's code, documentation, and procedures.

To understand your contribution, you must write it. Therefore, AI/LLM generated contributions
are not welcome.

## 🖖 Code of Conduct

We follow the [Rust Code of Conduct](http://www.rust-lang.org/conduct.html),
with the following additional clauses:

* We respect the rights to privacy and anonymity for contributors and people in
  the community.  If someone wishes to contribute under a pseudonym different to
  their primary identity, that wish is to be respected by all contributors.

## 🦀 MSRV Policy

The Minimum Supported Rust Version is whatever the current stable Rust release is when a ZebraChain
release is made.

## 🦀 SemVer Policy

There will be one. There is not one yet and there wont be one till the 0.1.0 release.

[crate-image]: https://img.shields.io/crates/v/zf-zebrachain?logo=rust
[crate-link]: https://crates.io/crates/zf-zebrachain
[docs-image]: https://docs.rs/zf-zebrachain/badge.svg
[docs-link]: https://docs.rs/zf-zebrachain
