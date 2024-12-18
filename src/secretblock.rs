use crate::secrets::Seed;
use crate::tunable::*;
use blake3::{hash, Hash};

fn check_secret_buf(buf: &[u8]) {
    if buf.len() != SECRET_BLOCK {
        panic!("Need a {SECRET_BLOCK} byte slice; got {} bytes", buf.len());
    }
}

fn get_hash(buf: &[u8], index: usize) -> Hash {
    let range = index * DIGEST..(index + 1) * DIGEST;
    Hash::from_bytes(buf[range].try_into().unwrap())
}

#[derive(Debug, PartialEq)]
struct SecretBlockInfo {
    pub block_hash: Hash,
    pub secret: Hash,
    pub next_secret: Hash,
    pub state_hash: Hash,
    pub previous_hash: Hash,
}

#[derive(Debug, PartialEq)]
pub enum SecretBlockError {
    Content,
    Seed,
    SeedSequence,
    Hash,
    PreviousHash,
}

pub type SecretBlockResult<'a> = Result<SecretBlock<'a>, SecretBlockError>;

#[derive(Debug)]
pub struct SecretBlock<'a> {
    buf: &'a [u8],
    pub info: SecretBlockInfo,
}

impl<'a> SecretBlock<'a> {
    fn new(buf: &'a [u8]) -> Self {
        check_secret_buf(buf);
        let block_hash = get_hash(buf, 0);
        let secret = get_hash(buf, 1);
        let next_secret = get_hash(buf, 2);
        let state_hash = get_hash(buf, 3);
        let previous_hash = get_hash(buf, 4);
        let info = SecretBlockInfo {
            block_hash,
            secret,
            next_secret,
            state_hash,
            previous_hash,
        };
        Self { buf, info }
    }

    fn compute_hash(&self) -> Hash {
        hash(&self.buf[DIGEST..])
    }

    fn content_is_valid(&self) -> bool {
        self.info.block_hash == self.compute_hash()
    }

    pub fn open(buf: &'a [u8]) -> SecretBlockResult<'a> {
        let block = Self::new(buf);
        if !block.content_is_valid() {
            Err(SecretBlockError::Content)
        } else if block.info.secret == block.info.next_secret {
            Err(SecretBlockError::Seed)
        } else {
            Ok(block)
        }
    }

    pub fn from_hash(buf: &'a [u8], block_hash: &Hash) -> SecretBlockResult<'a> {
        let block = Self::open(buf)?;
        if block_hash != &block.info.block_hash {
            Err(SecretBlockError::Hash)
        } else {
            Ok(block)
        }
    }

    pub fn from_previous(buf: &'a [u8], info: &SecretBlockInfo) -> SecretBlockResult<'a> {
        let block = Self::open(buf)?;
        if block.info.previous_hash != info.block_hash {
            Err(SecretBlockError::PreviousHash)
        } else if block.info.secret != info.next_secret {
            Err(SecretBlockError::SeedSequence)
        } else {
            Ok(block)
        }
    }
}

#[derive(Debug)]
pub struct MutSecretBlock<'a> {
    buf: &'a mut [u8],
}

impl<'a> MutSecretBlock<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        check_secret_buf(buf);
        buf.fill(0);
        Self { buf }
    }

    fn as_hashable(&self) -> &[u8] {
        &self.buf[DIGEST..]
    }

    fn set_seed(&mut self, seed: &Seed) {
        self.buf[SECRET_RANGE].copy_from_slice(seed.secret.as_bytes());
        self.buf[NEXT_SECRET_RANGE].copy_from_slice(seed.next_secret.as_bytes());
    }

    fn set_state_hash(&mut self, state_hash: &Hash) {
        self.buf[SECRET_STATE_RANGE].copy_from_slice(state_hash.as_bytes());
    }

    fn set_previous_hash(&mut self, previous_hash: &Hash) {
        self.buf[SECRET_PREVIOUS_RANGE].copy_from_slice(previous_hash.as_bytes());
    }

    fn finalize(mut self) -> Hash {
        let block_hash = hash(self.as_hashable());
        self.buf[0..DIGEST].copy_from_slice(block_hash.as_bytes());
        block_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_secret_buf() {
        let buf = [0; SECRET_BLOCK];
        check_secret_buf(&buf);
        assert_eq!(buf, [0; SECRET_BLOCK]);
    }

    #[test]
    #[should_panic(expected = "Need a 160 byte slice; got 159 bytes")]
    fn test_check_secret_buf_panic_low() {
        let buf = [0; SECRET_BLOCK - 1];
        check_secret_buf(&buf);
    }

    #[test]
    #[should_panic(expected = "Need a 160 byte slice; got 161 bytes")]
    fn test_check_secret_buf_panic_high() {
        let buf = [0; SECRET_BLOCK + 1];
        check_secret_buf(&buf);
    }

    #[test]
    fn test_mut_block_new() {
        let mut buf = [69; SECRET_BLOCK];
        let mut block = MutSecretBlock::new(&mut buf);
        assert_eq!(buf, [0; SECRET_BLOCK]);
    }

    #[test]
    fn test_mut_block_set_seed() {
        let seed = Seed::create(&[69; 32]);
        let mut buf = [0; SECRET_BLOCK];
        let mut block = MutSecretBlock::new(&mut buf);
        block.set_seed(&seed);
        assert_eq!(
            buf,
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 126, 181, 75, 23, 139, 24, 30, 103, 78, 67, 183, 50, 113, 40, 111, 123,
                177, 241, 207, 25, 212, 110, 114, 199, 42, 230, 214, 104, 228, 129, 178, 174, 175,
                79, 81, 160, 51, 80, 28, 213, 210, 42, 68, 97, 174, 58, 207, 124, 133, 195, 216,
                186, 106, 75, 254, 114, 141, 255, 123, 152, 135, 170, 146, 150, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0
            ]
        );
    }
}
