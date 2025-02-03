# 🦓 ZebraChain 🦓

[![Build Status](https://github.com/zebrafactory/zebrachain/actions/workflows/rust.yml/badge.svg)](https://github.com/zebrafactory/zebrachain/actions)

ZebraChain is a logged, quantum safe signing protocol designed to replace the long lived asymmetric
key pairs used to sign software releases (and to sign other super important stuff).

Consider the GPG key used to sign updates for your favorite Linux distribution.  You could replace
it with a ZebraChain, gaining some important benefits over the GPG key:

* Each signature is a new block in a blockchain, with a back-reference to the hash of the previous
block.  This creates a robust, publicly verifiable log of every signature that has be made using a
specific ZebraChain.

* A given asymmetric key pair is only used *once!* Each block contains the signature, the
corresponding public key used to sign the block, and a *forward-reference* to the *hash* of the
coresponding public key that will be used to sign the *next* block. This allows new entropy to be
introduced at each signature, minimizing the problem of whether there was high enough quality
entropy when the first secret key in the ZebraChain was created.

* Quantum safe (assuming the Dilithium + ed25519 hybrid construction is quantum safe).

* *Some* quantum mitigation, even if Dilithium is broken.  A sufficiently large quantum computer can
get the secret key from an ed25519 public key (that's the whole problem).  But that same quantum
computer *cannot* get the ed25519 public key from the *hash* of that public key. So if consumers of
the chain locally checkpoint the hash of the latest block, a quantum attack cannot be attempted
until the owner of the ZebraChain publishes their next valid signature block (after which the public
key for the block is exposed, allowing a quantum attacker to get the secret key and forge arbitrary
signatures for that position in the chain).

In the near term ZebraChain needs to configurable to support all the [NIST post quantum standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards) and multiple hash algorithms.  It must be possible to add new algorithms in the future.

But the current focus is on building a simple, non-configurable reference implementation using:

* A [Dilithium](https://pq-crystals.org/dilithium/) + [ed25519](https://ed25519.cr.yp.to/) hybrid
construction for signing

* [Blake3](https://github.com/BLAKE3-team/BLAKE3) for hashing


## Wire Format

A ZebraChain block has 10 fields currently:

```
HASH SIG PUB NEXT_PUB_HASH TIME AUTH_HASH STATE_HASH INDEX PREV_HASH CHAIN_HASH
```

Where:

```
HASH = hash(SIG PUB NEXT_PUB_HASH TIME AUTH_HASH STATE_HASH INDEX PREV_HASH CHAIN_HASH)
```

And where:

```
SIG = sign(PUB NEXT_PUB_HASH TIME AUTH_HASH STATE_HASH INDEX PREV_HASH CHAIN_HASH)
```
