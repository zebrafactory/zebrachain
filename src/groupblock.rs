use crate::{DIGEST, Hash, PermissionError};
use std::collections::HashMap;

/// Which users (and via which public keys) can sign the next block.
#[derive(Debug)]
pub struct GroupPermission {
    map: HashMap<Hash, Hash>,
}

impl GroupPermission {
    /// Create new empty `GroupPermission`.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Specify that the `user_hash` chain can sign the next block with a public key with `pubkey_hash`.
    pub fn insert(&mut self, user_hash: Hash, pubkey_hash: Hash) -> Result<(), PermissionError> {
        if self.map.contains_key(&user_hash) {
            Err(PermissionError::BadInsert)
        } else {
            self.map.insert(user_hash, pubkey_hash);
            Ok(())
        }
    }

    /// Update permissions to be signed by this user next block but with a new public key.
    pub fn replace(&mut self, user_hash: Hash, pubkey_hash: Hash) -> Result<(), PermissionError> {
        if self.map.contains_key(&user_hash) {
            self.map.insert(user_hash, pubkey_hash);
            Ok(())
        } else {
            Err(PermissionError::BadReplace)
        }
    }

    /// Serialize permissions.
    pub fn write_to_buf(&self, buf: &mut [u8]) -> Result<(), PermissionError> {
        if self.map.is_empty() {
            Err(PermissionError::Empty)
        } else if buf.is_empty() || buf.len() != self.map.len() * DIGEST * 2 {
            Err(PermissionError::Length)
        } else {
            let mut pairs = Vec::from_iter(self.map.iter());
            pairs.sort();
            let mut offset = 0;
            for (user_hash, pubkey_hash) in &pairs {
                buf[offset..offset + DIGEST].copy_from_slice(user_hash.as_bytes());
                offset += DIGEST;
                buf[offset..offset + DIGEST].copy_from_slice(pubkey_hash.as_bytes());
                offset += DIGEST;
            }
            Ok(())
        }
    }

    /// Deserialize permissions.
    pub fn from_buf(buf: &[u8]) -> Result<Self, PermissionError> {
        if buf.is_empty() || buf.len() % (DIGEST * 2) != 0 {
            Err(PermissionError::Length)
        } else {
            let mut perm = GroupPermission::new();
            for i in 0..buf.len() / (DIGEST * 2) {
                let a = i * DIGEST * 2;
                let b = a + DIGEST;
                let c = b + DIGEST;
                let user_hash = Hash::from_slice(&buf[a..b]).unwrap();
                let pubkey_hash = Hash::from_slice(&buf[b..c]).unwrap();
                perm.insert(user_hash, pubkey_hash)?;
            }
            Ok(perm)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhelpers::random_hash;

    #[test]
    fn test_group_permission_new() {
        let gp = GroupPermission::new();
        assert!(gp.map.is_empty());
    }

    #[test]
    fn test_group_permission_insert() {
        let user_hash = random_hash();
        let pubkey_hash = random_hash();
        let mut gp = GroupPermission::new();
        assert_eq!(gp.insert(user_hash.clone(), pubkey_hash.clone()), Ok(()));
        assert_eq!(
            gp.insert(user_hash.clone(), pubkey_hash.clone()),
            Err(PermissionError::BadInsert)
        );
    }

    #[test]
    fn test_group_permission_replace() {
        let user_hash = random_hash();
        let pubkey_hash = random_hash();
        let mut gp = GroupPermission::new();
        assert_eq!(
            gp.replace(user_hash.clone(), pubkey_hash.clone()),
            Err(PermissionError::BadReplace)
        );
        gp.map.insert(user_hash.clone(), pubkey_hash.clone()); // FIXME, we didn't change the key
        assert_eq!(gp.replace(user_hash, pubkey_hash), Ok(()));
    }

    #[test]
    fn test_ground_permission_write_to_buf() {
        let mut gp = GroupPermission::new();
        let mut buf = [0; DIGEST * 4];
        assert_eq!(gp.write_to_buf(&mut buf), Err(PermissionError::Empty));
        let user0_hash = random_hash();
        let pubkey0_hash = random_hash();
        gp.insert(user0_hash.clone(), pubkey0_hash.clone()).unwrap();

        let user1_hash = random_hash();
        let pubkey1_hash = random_hash();
        gp.insert(user1_hash.clone(), pubkey1_hash.clone()).unwrap();

        assert_eq!(gp.write_to_buf(&mut buf), Ok(()));
    }

    #[test]
    fn test_group_permission_roundtrip() {
        let user_hash = random_hash();
        let pubkey_hash = random_hash();
        let mut gp = GroupPermission::new();
        gp.insert(user_hash.clone(), pubkey_hash.clone()).unwrap();

        let mut buf = [0; DIGEST * 2];
        gp.write_to_buf(&mut buf).unwrap();
        let gp = GroupPermission::from_buf(&buf).unwrap();
        let mut expected = HashMap::new();
        assert_ne!(gp.map, expected);
        expected.insert(user_hash, pubkey_hash);
        assert_eq!(gp.map, expected);
    }
}
