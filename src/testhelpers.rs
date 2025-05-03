//! Some test fixtures only built on `cfg(test)`.

use crate::payload::Payload;
use blake3::Hash;
use getrandom;

/// Returns a random u64 created with [getradom::fill()].
pub fn random_u64() -> u64 {
    let mut buf = [0; 8];
    getrandom::fill(&mut buf).unwrap();
    u64::from_le_bytes(buf)
}

/// Returns a random [blake3::Hash] created with [getradom::fill()].
pub fn random_hash() -> Hash {
    let mut buf = [0; 32];
    getrandom::fill(&mut buf).unwrap();
    Hash::from_bytes(buf)
}

/// Returns a random [Payload].
pub fn random_payload() -> Payload {
    Payload::new(random_u64(), random_hash())
}

/// Returns a vec of random payloads.
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

/// Iteration through all 1-bit flip permutations in a buffer.
#[derive(Debug)]
pub struct BitFlipper {
    good: Vec<u8>,
    counter: usize,
}

impl BitFlipper {
    /// Create a new [BitFlipper].
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

/// Iteration through all 1-bit flip permutations in a [blake3::Hash].
#[derive(Debug)]
pub struct HashBitFlipper {
    orig: Hash,
    counter: usize,
}

impl HashBitFlipper {
    /// Create a new [HashBitFlipper].
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

/// Iteration through all 1-bit flip permutations in a u64.
#[derive(Debug)]
pub struct U64BitFlipper {
    orig: [u8; 8],
    counter: usize,
}

impl U64BitFlipper {
    /// Create a new [HashBitFlipper].
    pub fn new(orig: u64) -> Self {
        Self {
            orig: orig.to_le_bytes(),
            counter: 0,
        }
    }
}

impl Iterator for U64BitFlipper {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        if self.counter < self.orig.len() * 8 {
            let mut bad = self.orig;
            flip_bit(&mut bad, self.counter);
            self.counter += 1;
            Some(u64::from_le_bytes(bad))
        } else {
            None
        }
    }
}

/// Iteration through all 1-bit flip permutations in a u128.
#[derive(Debug)]
pub struct U128BitFlipper {
    orig: [u8; 16],
    counter: usize,
}

impl U128BitFlipper {
    /// Create a new [HashBitFlipper].
    pub fn new(orig: u128) -> Self {
        Self {
            orig: orig.to_le_bytes(),
            counter: 0,
        }
    }
}

impl Iterator for U128BitFlipper {
    type Item = u128;

    fn next(&mut self) -> Option<Self::Item> {
        if self.counter < self.orig.len() * 8 {
            let mut bad = self.orig;
            flip_bit(&mut bad, self.counter);
            self.counter += 1;
            Some(u128::from_le_bytes(bad))
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

    #[test]
    fn test_u64_bit_flipper() {
        let orig = random_u64();
        let mut hset: HashSet<u64> = HashSet::new();
        assert!(hset.insert(orig));
        for bad in U64BitFlipper::new(orig) {
            assert!(hset.insert(bad));
        }
        assert_eq!(hset.len(), 65);
    }
}
