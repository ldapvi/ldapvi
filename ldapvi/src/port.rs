use md5::Md5;
use sha1::{Digest as _, Sha1};

use crate::base64;

/// Compute SHA1 hash of `key` and append as base64.
pub fn append_sha(dst: &mut String, key: &str) {
    let hash = Sha1::digest(key.as_bytes());
    base64::append_base64(dst, &hash);
}

/// Compute salted SHA1 hash of `key` and append as base64.
/// Uses a random 4-byte salt appended after the hash.
pub fn append_ssha(dst: &mut String, key: &str) {
    append_ssha_with_salt(dst, key, &random_salt())
}

fn append_ssha_with_salt(dst: &mut String, key: &str, salt: &[u8; 4]) {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(salt);
    let hash = hasher.finalize();
    let mut combined = Vec::with_capacity(hash.len() + salt.len());
    combined.extend_from_slice(&hash);
    combined.extend_from_slice(salt);
    base64::append_base64(dst, &combined);
}

/// Compute MD5 hash of `key` and append as base64.
pub fn append_md5(dst: &mut String, key: &str) {
    let hash = Md5::digest(key.as_bytes());
    base64::append_base64(dst, &hash);
}

/// Compute salted MD5 hash of `key` and append as base64.
/// Uses a random 4-byte salt appended after the hash.
pub fn append_smd5(dst: &mut String, key: &str) {
    append_smd5_with_salt(dst, key, &random_salt())
}

fn append_smd5_with_salt(dst: &mut String, key: &str, salt: &[u8; 4]) {
    let mut hasher = Md5::new();
    hasher.update(key.as_bytes());
    hasher.update(salt);
    let hash = hasher.finalize();
    let mut combined = Vec::with_capacity(hash.len() + salt.len());
    combined.extend_from_slice(&hash);
    combined.extend_from_slice(salt);
    base64::append_base64(dst, &combined);
}

fn random_salt() -> [u8; 4] {
    let mut salt = [0u8; 4];
    // Use getrandom for portability; fall back to /dev/urandom
    #[cfg(target_family = "unix")]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let _ = f.read_exact(&mut salt);
        }
    }
    salt
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base64::read_base64;

    #[test]
    fn sha_produces_20_bytes() {
        let mut s = String::new();
        append_sha(&mut s, "hello");
        let decoded = read_base64(&s).unwrap();
        assert_eq!(decoded.len(), 20); // SHA1 = 20 bytes
    }

    #[test]
    fn sha_deterministic() {
        let mut s1 = String::new();
        let mut s2 = String::new();
        append_sha(&mut s1, "hello");
        append_sha(&mut s2, "hello");
        assert_eq!(s1, s2);
    }

    #[test]
    fn ssha_produces_24_bytes() {
        let mut s = String::new();
        append_ssha_with_salt(&mut s, "hello", &[1, 2, 3, 4]);
        let decoded = read_base64(&s).unwrap();
        assert_eq!(decoded.len(), 24); // SHA1(20) + salt(4)
    }

    #[test]
    fn ssha_salt_appended() {
        let salt = [0xAA, 0xBB, 0xCC, 0xDD];
        let mut s = String::new();
        append_ssha_with_salt(&mut s, "hello", &salt);
        let decoded = read_base64(&s).unwrap();
        assert_eq!(&decoded[20..], &salt);
    }

    #[test]
    fn md5_produces_16_bytes() {
        let mut s = String::new();
        append_md5(&mut s, "hello");
        let decoded = read_base64(&s).unwrap();
        assert_eq!(decoded.len(), 16); // MD5 = 16 bytes
    }

    #[test]
    fn md5_deterministic() {
        let mut s1 = String::new();
        let mut s2 = String::new();
        append_md5(&mut s1, "hello");
        append_md5(&mut s2, "hello");
        assert_eq!(s1, s2);
    }

    #[test]
    fn smd5_produces_20_bytes() {
        let salt = [1, 2, 3, 4];
        let mut s = String::new();
        append_smd5_with_salt(&mut s, "hello", &salt);
        let decoded = read_base64(&s).unwrap();
        assert_eq!(decoded.len(), 20); // MD5(16) + salt(4)
    }

    #[test]
    fn smd5_salt_appended() {
        let salt = [0x11, 0x22, 0x33, 0x44];
        let mut s = String::new();
        append_smd5_with_salt(&mut s, "hello", &salt);
        let decoded = read_base64(&s).unwrap();
        assert_eq!(&decoded[16..], &salt);
    }

    #[test]
    fn different_keys_different_sha() {
        let mut s1 = String::new();
        let mut s2 = String::new();
        append_sha(&mut s1, "hello");
        append_sha(&mut s2, "world");
        assert_ne!(s1, s2);
    }

    #[test]
    fn different_keys_different_md5() {
        let mut s1 = String::new();
        let mut s2 = String::new();
        append_md5(&mut s1, "hello");
        append_md5(&mut s2, "world");
        assert_ne!(s1, s2);
    }
}
