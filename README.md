# 🦓 ZebraChain 🦓

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

* Quantum mitigation, even if Dilithium is broken.  A sufficiently large
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

Current focus is on building up a simple reference implementation step by step
and getting broad feedback and reveiew.
