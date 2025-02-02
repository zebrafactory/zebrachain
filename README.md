# 🦓 ZebraChain 🦓

[![Build Status](https://github.com/zebrafactory/zebrachain/actions/workflows/rust.yml/badge.svg)](https://github.com/zebrafactory/zebrachain/actions)

ZebraChain is designed to the replace long lived secret keys used to sign
software releases (or to sign other super important stuff).

Consider the GPG key used to sign your favorite Linux distribution.  You could
replace it with a ZebraChain, gaining some important benefits over the GPG key:

* Each signature is a new block in a blockchain, with a back-reference to the
hash of the previous block.  This creates a robust, verifiable log of each and
every time a signature has be made using a specific ZebraChain.

* A given public key is only used *once!* Each block contains the signature, the
public key used to to sign the block, and a *forward-reference* to the *hash* of
the public key that will be used to sign the *next* block.  This allows new
entropy to be introduced at each signature, minimizing the problem of whether
there was high enough quality entropy when the first secret key in the
ZebraChain was created.

* Quantum safe (assuming the Dilithium + ed25519 hybrid construction is quantum
safe).

* *Some* quantum mitigation, even if Dilithium is broken.  A sufficiently large
quantum computer can get the secret key from an ed25519 public key (that's the
whole problem).  But that same quantum computer *cannot* get the ed25519 public
key from the *hash* of that public key.  So if consumers of the chain locally
checkpoint the hash of the latest block, a quantum attack cannot be attempted
until the owner of the ZebraChain publishes their next valid signature block
(after which the public key for the block is exposed, allowing a quantum
attacker to get the secret key and forge arbitrary signatures for that position
in the chain).

* Why not checkpoint ZebraChains in other ZebraChains?  That could build a vast
network of cross checkedpointed chains that would likely be very difficult to
attack in practice. There will be a lot more to say on this soon, but the
general design philosophy is: public key crypto weak, hash crypto strong.  So
we want to verify by the signature only if essential, and otherwise move onto
relying on the hash instead.

In the near term ZebraChain needs to configurable to support all the [NIST post quantum standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards) and multiple hash algorithms.  It must be possible to add new algorithms in the future.

But the current focus is on building a simple, non-configurable reference implementation using:

* A [Dilithium](https://pq-crystals.org/dilithium/) + [ed25519](https://ed25519.cr.yp.to/) hybrid construction for signing

* [Blake3](https://github.com/BLAKE3-team/BLAKE3) for hashing


## Wire Format

A ZebraChain block has 10 fields currently:

        HASH || SIG || PUB || NEXT_PUB_HASH || TIME || AUTH_HASH || STATE_HASH || INDEX || PREV_HASH || CHAIN_HASH
                ^^^^^^^^^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                From the `Seed`                From the `SigningRequest`          From the previous `BlockState`
Where:

        HASH = hash(SIG || PUB || NEXT_PUB_HASH || TIME || AUTH_HASH || STATE_HASH || INDEX || PREV_HASH || CHAIN_HASH)
                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

And where:

        SIG = sign(PUB || NEXT_PUB_HASH || TIME || AUTH_HASH || STATE_HASH || INDEX || PREV_HASH || CHAIN_HASH)
                                           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
