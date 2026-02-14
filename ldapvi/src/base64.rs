use std::io::{self, Write};

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const PAD64: u8 = b'=';

/// Encode `src` as base64, writing to `w` with LDIF-style line folding
/// (newline + space after every 76 characters of output).
pub fn print_base64(src: &[u8], w: &mut dyn Write) -> io::Result<()> {
    let mut col = 0;
    let mut i = 0;

    while i + 2 < src.len() {
        let input = [src[i], src[i + 1], src[i + 2]];
        i += 3;

        let output = [
            input[0] >> 2,
            ((input[0] & 0x03) << 4) | (input[1] >> 4),
            ((input[1] & 0x0f) << 2) | (input[2] >> 6),
            input[2] & 0x3f,
        ];

        if col >= 76 {
            w.write_all(b"\n ")?;
            col = 0;
        }
        col += 4;

        w.write_all(&[
            BASE64[output[0] as usize],
            BASE64[output[1] as usize],
            BASE64[output[2] as usize],
            BASE64[output[3] as usize],
        ])?;
    }

    let remaining = src.len() - i;
    if remaining > 0 {
        let mut input = [0u8; 3];
        input[..remaining].copy_from_slice(&src[i..i + remaining]);

        let output = [
            input[0] >> 2,
            ((input[0] & 0x03) << 4) | (input[1] >> 4),
            ((input[1] & 0x0f) << 2) | (input[2] >> 6),
        ];

        w.write_all(&[BASE64[output[0] as usize], BASE64[output[1] as usize]])?;
        if remaining == 1 {
            w.write_all(&[PAD64])?;
        } else {
            w.write_all(&[BASE64[output[2] as usize]])?;
        }
        w.write_all(&[PAD64])?;
    }

    Ok(())
}

/// Encode `src` as base64, appending to `dst` with LDIF-style line folding.
pub fn append_base64(dst: &mut String, src: &[u8]) {
    let mut buf = Vec::new();
    print_base64(src, &mut buf).unwrap();
    dst.push_str(&String::from_utf8(buf).unwrap());
}

/// Decode base64 `src` into bytes. Returns None on invalid input.
pub fn read_base64(src: &str) -> Option<Vec<u8>> {
    let mut target = Vec::new();
    let mut state = 0u8;
    let mut chars = src.bytes().peekable();

    while let Some(&ch) = chars.peek() {
        chars.next();

        if ch.is_ascii_whitespace() {
            continue;
        }

        if ch == PAD64 {
            // Handle padding
            match state {
                0 | 1 => return None,
                2 => {
                    // Skip whitespace, expect another '='
                    while let Some(&c) = chars.peek() {
                        if !c.is_ascii_whitespace() {
                            break;
                        }
                        chars.next();
                    }
                    match chars.next() {
                        Some(c) if c == PAD64 => {}
                        _ => return None,
                    }
                    // Fall through to check trailing
                    for c in chars {
                        if !c.is_ascii_whitespace() {
                            return None;
                        }
                    }
                    // Check extra bits are zero
                    if let Some(&last) = target.last() {
                        if last != 0 {
                            return None;
                        }
                        target.pop();
                    }
                    return Some(target);
                }
                3 => {
                    // Check trailing whitespace only
                    for c in chars {
                        if !c.is_ascii_whitespace() {
                            return None;
                        }
                    }
                    // Check extra bits are zero
                    if let Some(&last) = target.last() {
                        if last != 0 {
                            return None;
                        }
                        target.pop();
                    }
                    return Some(target);
                }
                _ => unreachable!(),
            }
        }

        let pos = match BASE64.iter().position(|&b| b == ch) {
            Some(p) => p as u8,
            None => return None,
        };

        match state {
            0 => {
                target.push(pos << 2);
                state = 1;
            }
            1 => {
                let last = target.last_mut().unwrap();
                *last |= pos >> 4;
                target.push((pos & 0x0f) << 4);
                state = 2;
            }
            2 => {
                let last = target.last_mut().unwrap();
                *last |= pos >> 2;
                target.push((pos & 0x03) << 6);
                state = 3;
            }
            3 => {
                let last = target.last_mut().unwrap();
                *last |= pos;
                state = 0;
            }
            _ => unreachable!(),
        }
    }

    if state != 0 {
        return None;
    }

    Some(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_empty() {
        let mut buf = Vec::new();
        print_base64(b"", &mut buf).unwrap();
        assert_eq!(buf, b"");
    }

    #[test]
    fn encode_hello() {
        let mut buf = Vec::new();
        print_base64(b"hello", &mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "aGVsbG8=");
    }

    #[test]
    fn encode_one_byte() {
        let mut buf = Vec::new();
        print_base64(b"a", &mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "YQ==");
    }

    #[test]
    fn encode_two_bytes() {
        let mut buf = Vec::new();
        print_base64(b"ab", &mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "YWI=");
    }

    #[test]
    fn encode_three_bytes() {
        let mut buf = Vec::new();
        print_base64(b"abc", &mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "YWJj");
    }

    #[test]
    fn decode_hello() {
        let decoded = read_base64("aGVsbG8=").unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn decode_one_byte() {
        let decoded = read_base64("YQ==").unwrap();
        assert_eq!(decoded, b"a");
    }

    #[test]
    fn decode_two_bytes() {
        let decoded = read_base64("YWI=").unwrap();
        assert_eq!(decoded, b"ab");
    }

    #[test]
    fn decode_three_bytes() {
        let decoded = read_base64("YWJj").unwrap();
        assert_eq!(decoded, b"abc");
    }

    #[test]
    fn decode_invalid() {
        assert!(read_base64("!!!").is_none());
    }

    #[test]
    fn decode_with_whitespace() {
        let decoded = read_base64("YWJj\n ZGVm").unwrap();
        assert_eq!(decoded, b"abcdef");
    }

    #[test]
    fn roundtrip() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let mut encoded = String::new();
        append_base64(&mut encoded, data);
        let decoded = read_base64(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn roundtrip_binary() {
        let data: Vec<u8> = (0..=255).collect();
        let mut encoded = String::new();
        append_base64(&mut encoded, &data);
        let decoded = read_base64(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn line_folding() {
        // 57 bytes of input produces exactly 76 chars of base64 (no folding)
        // 58+ bytes should trigger folding
        let data = vec![0xFFu8; 60];
        let mut buf = Vec::new();
        print_base64(&data, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("\n "), "expected line folding in: {}", s);
    }
}
