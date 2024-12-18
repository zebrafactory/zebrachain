use crate::tunable::*;

fn check_secret_buf(buf: &[u8]) {
    if buf.len() != SECRET_BLOCK {
        panic!("Need a {SECRET_BLOCK} byte slice; got {} bytes", buf.len());
    }
}

#[derive(Debug)]
pub struct SecretBlock<'a> {
    buf: &'a [u8],
}

impl<'a> SecretBlock<'a> {
    fn new(buf: &'a [u8]) -> Self {
        check_secret_buf(buf);
        Self { buf }
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
}
