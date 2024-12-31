//! File system related utilities.
//!
//! For correctness and security, only open files using [create_for_append()] and
//! [open_for_append()].
//!
//! See [std::fs::OpenOptions] for more details.

use std::fs::File;
use std::io;
use std::path::Path;

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
    use tempfile;

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
