//! File system related utilities.
//!
//! For correctness and security, only open files using [create_for_append()] and
//! [open_for_append()].
//!
//! See [std::fs::OpenOptions] for more details.

use blake3::Hash;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// Build a chain filename in `dir` using hex representation of `chain_hash`.
///
/// # Example
///
/// ```
/// use zf_zebrachain::fsutil::chain_filename;
/// use blake3::Hash;
/// use std::path::PathBuf;
/// let dir = PathBuf::from("/tmp");
/// let chain_hash = Hash::from_bytes([69; 32]);
/// assert_eq!(
///     chain_filename(&dir, &chain_hash),
///     PathBuf::from("/tmp/4545454545454545454545454545454545454545454545454545454545454545")
/// );
/// ```
pub fn chain_filename(dir: &Path, chain_hash: &Hash) -> PathBuf {
    dir.join(format!("{chain_hash}"))
}

/// Build a secret chain filename in `dir` using hex representation of `chain_hash`.
///
/// # Example
///
/// ```
/// use zf_zebrachain::fsutil::secret_chain_filename;
/// use blake3::Hash;
/// use std::path::PathBuf;
/// let dir = PathBuf::from("/tmp");
/// let chain_hash = Hash::from_bytes([69; 32]);
/// assert_eq!(
///     secret_chain_filename(&dir, &chain_hash),
///     PathBuf::from("/tmp/4545454545454545454545454545454545454545454545454545454545454545.secret")
/// );
/// ```
pub fn secret_chain_filename(dir: &Path, chain_hash: &Hash) -> PathBuf {
    let mut filename = chain_filename(dir, chain_hash);
    filename.set_extension("secret");
    filename
}

/// Create a new file for read + append.
///
/// # Errors
///
/// This will return an `Err` if the path already exists.
pub fn create_for_append(path: &Path) -> io::Result<File> {
    File::options()
        .read(true)
        .append(true)
        .create_new(true)
        .open(path)
}

/// Open an existing file for read + append.
///
/// # Errors
///
/// This will return an `Err` if the path is not a file.
pub fn open_for_append(path: &Path) -> io::Result<File> {
    File::options().read(true).append(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhelpers::random_hash;
    use std::collections::HashSet;
    use tempfile;

    #[test]
    fn test_chain_filename() {
        let count = 1776;
        let mut names = HashSet::new();
        let dir = PathBuf::from("/stuff/junk");
        for _ in 0..count {
            let pb = chain_filename(&dir, &random_hash());
            assert!(names.insert(pb));
        }
        assert!(names.insert(dir));
        assert_eq!(names.len(), count + 1);
    }

    #[test]
    fn test_create_for_append() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let filename = tmpdir.path().join("foo");
        assert!(create_for_append(&filename).is_ok());
        assert!(create_for_append(&filename).is_err());
    }

    #[test]
    fn test_open_for_append() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let filename = tmpdir.path().join("foo");
        assert!(open_for_append(&filename).is_err());
        assert!(create_for_append(&filename).is_ok());
        assert!(open_for_append(&filename).is_ok());
    }
}
