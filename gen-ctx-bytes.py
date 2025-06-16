from os import urandom

names = [
    'CONTEXT_SECRET',
    'CONTEXT_SECRET_NEXT',
    'CONTEXT_ED25519',
    'CONTEXT_ML_DSA',
    'CONTEXT_SLH_DSA',
    'CONTEXT_CHAIN_SALT'
    'CONTEXT_STORE_KEY',
    'CONTEXT_STORE_NONCE',
]

template = '''pub(crate) static {}: &[u8; CONTEXT] =
    &hex!("{}");'''

for n in names:
    print(template.format(n, urandom(48).hex()))


