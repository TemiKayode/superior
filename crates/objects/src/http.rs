//! Just enough HTTP/1.1 for the updater to fetch a file: the request's
//! words, and the head of a response read in place (its status and its
//! `Content-Length`; a body without one, chunked or not, is refused).

/// The largest response head read.
pub const MAX_HEAD: usize = 1024;

/// A response's head, once it has all arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    /// The status code (200, 204, 404...).
    pub status: u16,
    /// The body's length, from `Content-Length`; 0 for a status that
    /// carries no body (1xx, 204, 304).
    pub length: usize,
    /// Where the body starts, past the blank line.
    pub body: usize,
}

/// Why a response's head was not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpError {
    /// The blank line ending it has not arrived yet.
    Incomplete,
    /// Not an HTTP/1.x status line, or a header line malformed.
    Malformed,
    /// A body without a `Content-Length` (chunked, or to the close).
    NoLength,
    /// Longer than `MAX_HEAD` without ending.
    TooLong,
}

/// The head of the response whose first bytes are `b`.
pub fn head(b: &[u8]) -> Result<Head, HttpError> {
    let Some(end) = b.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Err(if b.len() > MAX_HEAD { HttpError::TooLong } else { HttpError::Incomplete });
    };
    let mut lines = b[..end].split(|&c| c == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let status_line = lines.next().ok_or(HttpError::Malformed)?;
    let mut words = status_line.split(|&c| c == b' ');
    let version = words.next().ok_or(HttpError::Malformed)?;
    let code = words.next().ok_or(HttpError::Malformed)?;
    if !version.starts_with(b"HTTP/1.") || code.len() != 3 || !code.iter().all(u8::is_ascii_digit) {
        return Err(HttpError::Malformed);
    }
    let status = code.iter().fold(0u16, |n, d| n * 10 + (d - b'0') as u16);
    let mut length = None;
    for line in lines {
        let colon = line.iter().position(|&c| c == b':').ok_or(HttpError::Malformed)?;
        let (name, value) = (&line[..colon], trim(&line[colon + 1..]));
        if name.eq_ignore_ascii_case(b"content-length") {
            if value.is_empty() || value.len() > 10 || !value.iter().all(u8::is_ascii_digit) {
                return Err(HttpError::Malformed);
            }
            let n = value.iter().fold(0usize, |n, d| n * 10 + (d - b'0') as usize);
            if length.is_some_and(|l| l != n) {
                return Err(HttpError::Malformed);
            }
            length = Some(n);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err(HttpError::NoLength);
        }
    }
    let bodiless = (100..200).contains(&status) || status == 204 || status == 304;
    let length = if bodiless { 0 } else { length.ok_or(HttpError::NoLength)? };
    Ok(Head { status, length, body: end + 4 })
}

fn trim(mut v: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = v {
        v = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = v {
        v = rest;
    }
    v
}

/// Writes a `GET` of `path` from `host` (as `Host:` names it) into
/// `out`, the connection to close after: how many bytes, or `None` if
/// they do not fit.
pub fn get(out: &mut [u8], host: core::fmt::Arguments, path: core::fmt::Arguments) -> Option<usize> {
    use core::fmt::Write;
    struct W<'a>(&'a mut [u8], usize);
    impl Write for W<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let to = self.0.get_mut(self.1..self.1 + s.len()).ok_or(core::fmt::Error)?;
            to.copy_from_slice(s.as_bytes());
            self.1 += s.len();
            Ok(())
        }
    }
    let mut w = W(out, 0);
    write!(w, "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").ok()?;
    Some(w.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_head_and_finds_the_body() {
        let r = b"HTTP/1.1 200 OK\r\nServer: x\r\ncontent-length:  1234 \r\n\r\nBODY";
        assert_eq!(head(r), Ok(Head { status: 200, length: 1234, body: r.len() - 4 }));
        let r = b"HTTP/1.0 204 No Content\r\n\r\n";
        assert_eq!(head(r), Ok(Head { status: 204, length: 0, body: r.len() }));
        let r = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(head(r).unwrap().status, 404);
    }

    #[test]
    fn waits_for_the_whole_head() {
        assert_eq!(head(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n"), Err(HttpError::Incomplete));
        assert_eq!(head(&[b'a'; MAX_HEAD + 1]), Err(HttpError::TooLong));
    }

    #[test]
    fn refuses_what_it_cannot_follow() {
        assert_eq!(head(b"HTTP/1.1 200 OK\r\n\r\n"), Err(HttpError::NoLength));
        assert_eq!(head(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"), Err(HttpError::NoLength));
        assert_eq!(head(b"SSH-2.0 hello\r\n\r\n"), Err(HttpError::Malformed));
        assert_eq!(head(b"HTTP/1.1 2000 OK\r\n\r\n"), Err(HttpError::Malformed));
        assert_eq!(head(b"HTTP/1.1 200 OK\r\nno colon\r\n\r\n"), Err(HttpError::Malformed));
        assert_eq!(head(b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n"), Err(HttpError::Malformed));
        let two = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n";
        assert_eq!(head(two), Err(HttpError::Malformed));
    }

    #[test]
    fn writes_a_request() {
        let mut b = [0u8; 128];
        let n = get(&mut b, format_args!("10.0.2.2:{}", 8090), format_args!("/system?have={}", 2)).unwrap();
        assert_eq!(&b[..n], b"GET /system?have=2 HTTP/1.1\r\nHost: 10.0.2.2:8090\r\nConnection: close\r\n\r\n");
        assert_eq!(get(&mut [0u8; 10], format_args!("h"), format_args!("/")), None);
    }
}
