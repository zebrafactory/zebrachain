//! Some test fixtures only built on `cfg(test)`.

use crate::payload::Payload;
use blake3::Hash;
use getrandom;

pub fn random_u64() -> u64 {
    let mut buf = [0; 8];
    getrandom::fill(&mut buf).unwrap();
    u64::from_le_bytes(buf)
}

pub fn random_hash() -> Hash {
    let mut buf = [0; 32];
    getrandom::fill(&mut buf).unwrap();
    Hash::from_bytes(buf)
}

pub fn random_payload() -> Payload {
    Payload::new(random_u64(), random_hash())
}

pub fn random_payload_vec(count: usize) -> Vec<Payload> {
    let mut payload_vec = Vec::with_capacity(count);
    for _ in 0..count {
        payload_vec.push(random_payload());
    }
    payload_vec
}

fn flip_bit(buf: &mut [u8], counter: usize) {
    let i = counter / 8;
    let b = (counter % 8) as u8;
    buf[i] ^= 1 << b; // Flip bit `b` in byte `i`
}

#[derive(Debug)]
pub struct BitFlipper {
    good: Vec<u8>,
    counter: usize,
}

impl BitFlipper {
    pub fn new(orig: &[u8]) -> Self {
        let mut good = Vec::with_capacity(orig.len());
        good.extend_from_slice(orig);
        BitFlipper { good, counter: 0 }
    }
}

impl Iterator for BitFlipper {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.counter < self.good.len() * 8 {
            let mut bad = Vec::with_capacity(self.good.len());
            bad.extend_from_slice(&self.good[..]);
            flip_bit(&mut bad[..], self.counter);
            self.counter += 1;
            Some(bad)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct HashBitFlipper {
    orig: Hash,
    counter: usize,
}

impl HashBitFlipper {
    pub fn new(orig: &Hash) -> Self {
        Self {
            orig: *orig,
            counter: 0,
        }
    }
}

impl Iterator for HashBitFlipper {
    type Item = Hash;

    fn next(&mut self) -> Option<Self::Item> {
        if self.counter < self.orig.as_bytes().len() * 8 {
            let mut bad = *self.orig.as_bytes();
            flip_bit(&mut bad, self.counter);
            self.counter += 1;
            Some(Hash::from_bytes(bad))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_bit_flipper() {
        let good: Vec<u8> = vec![0b01010101];
        let badies = Vec::from_iter(BitFlipper::new(&good[..]));
        assert_eq!(badies.len(), 8);
        assert_eq!(
            badies,
            vec![
                vec![0b01010100],
                vec![0b01010111],
                vec![0b01010001],
                vec![0b01011101],
                vec![0b01000101],
                vec![0b01110101],
                vec![0b00010101],
                vec![0b11010101],
            ]
        );

        let good: Vec<u8> = vec![0b00000000, 0b11111111];
        let badies = Vec::from_iter(BitFlipper::new(&good[..]));
        assert_eq!(badies.len(), 16);
        assert_eq!(
            badies,
            vec![
                vec![0b00000001, 0b11111111],
                vec![0b00000010, 0b11111111],
                vec![0b00000100, 0b11111111],
                vec![0b00001000, 0b11111111],
                vec![0b00010000, 0b11111111],
                vec![0b00100000, 0b11111111],
                vec![0b01000000, 0b11111111],
                vec![0b10000000, 0b11111111],
                vec![0b00000000, 0b11111110],
                vec![0b00000000, 0b11111101],
                vec![0b00000000, 0b11111011],
                vec![0b00000000, 0b11110111],
                vec![0b00000000, 0b11101111],
                vec![0b00000000, 0b11011111],
                vec![0b00000000, 0b10111111],
                vec![0b00000000, 0b01111111],
            ]
        );
    }

    #[test]
    fn test_hash_bit_flipper() {
        let orig = Hash::from_bytes([69; 32]);
        let mut hset: HashSet<Hash> = HashSet::new();
        assert!(hset.insert(orig));
        for bad in HashBitFlipper::new(&orig) {
            assert!(hset.insert(bad));
        }
        assert_eq!(hset.len(), 32 * 8 + 1);
    }
}
