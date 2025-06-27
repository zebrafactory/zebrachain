// File system related utilities.

use crate::Hash;
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};

pub(crate) fn read_retry(file: &mut io::BufReader<File>, buf: &mut [u8]) -> io::Result<usize> {
    let mut read = 0;
    loop {
        let new = file.read(&mut buf[read..])?;
        read += new;
        if read == buf.len() || new == 0 {
            return Ok(read);
        }
    }
}

pub(crate) fn chain_filename(dir: &Path, chain_hash: &Hash) -> PathBuf {
    dir.join(format!("{chain_hash}"))
}

pub(crate) fn secret_chain_filename(dir: &Path, chain_hash: &Hash) -> PathBuf {
    let mut filename = chain_filename(dir, chain_hash);
    filename.set_extension("secret");
    filename
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn create_for_append(path: &Path) -> io::Result<File> {
    File::options()
        .read(true)
        .append(true)
        .create_new(true)
        .open(path)
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn open_for_append(path: &Path) -> io::Result<File> {
    File::options().read(true).append(true).open(path)
}

#[cfg(target_os = "windows")]
pub(crate) fn create_for_append(path: &Path) -> io::Result<File> {
    File::options()
        .read(true)
        .write(true) // Must open in write mode on Windows in order to truncate
        .create_new(true)
        .open(path)
}

#[cfg(target_os = "windows")]
pub(crate) fn open_for_append(path: &Path) -> io::Result<File> {
    // Must open in write mode on Windows in order to truncate
    File::options().read(true).write(true).open(path)
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
