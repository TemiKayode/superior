//! Pictures from image files, read in place without allocating: Netpbm's
//! binary PPM (`P6`, RGB) and PAM (`P7`, `RGB` or `RGB_ALPHA`), 8 bits a
//! sample (`MAXVAL` 255). Comments (`#` to the end of a line) may come
//! anywhere in the header.

/// The widest and tallest image read.
pub const MAX_SIDE: usize = 1024;

/// Why an image file was not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageError {
    /// Neither `P6` nor `P7`.
    Format,
    /// A header missing a field, or with one it does not take.
    Header,
    /// No pixels, wider or taller than `MAX_SIDE`, or samples not 8 bits.
    Size,
    /// Fewer bytes than its pixels take.
    Short,
}

/// An image: its size and its pixels, row by row from the top, each
/// `DEPTH` bytes (red, green, blue and, with alpha, opacity).
#[derive(Clone, Copy, Debug)]
pub struct Image<'a> {
    pub width: usize,
    pub height: usize,
    alpha: bool,
    data: &'a [u8],
}

/// Reads a header's tokens: words between whitespace, comments skipped.
struct Header<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Header<'a> {
    fn token(&mut self) -> Option<&'a [u8]> {
        loop {
            match self.b.get(self.at)? {
                b'#' => {
                    while self.b.get(self.at).is_some_and(|&c| c != b'\n') {
                        self.at += 1;
                    }
                }
                c if c.is_ascii_whitespace() => self.at += 1,
                _ => break,
            }
        }
        let start = self.at;
        while self.b.get(self.at).is_some_and(|c| !c.is_ascii_whitespace() && *c != b'#') {
            self.at += 1;
        }
        Some(&self.b[start..self.at])
    }

    fn number(&mut self) -> Result<usize, ImageError> {
        let t = self.token().ok_or(ImageError::Header)?;
        if t.is_empty() || t.len() > 6 || !t.iter().all(u8::is_ascii_digit) {
            return Err(ImageError::Header);
        }
        Ok(t.iter().fold(0, |n, d| n * 10 + (d - b'0') as usize))
    }

    /// Past the one whitespace byte that ends the header.
    fn end(&mut self) -> Result<usize, ImageError> {
        match self.b.get(self.at) {
            Some(c) if c.is_ascii_whitespace() => Ok(self.at + 1),
            _ => Err(ImageError::Short),
        }
    }
}

impl<'a> Image<'a> {
    pub fn parse(b: &'a [u8]) -> Result<Image<'a>, ImageError> {
        let mut h = Header { b, at: 2 };
        let (width, height, depth, maxval, start) = match b.get(..2) {
            Some(b"P6") => {
                let (w, ht, max) = (h.number()?, h.number()?, h.number()?);
                (w, ht, 3, max, h.end()?)
            }
            Some(b"P7") => {
                let (mut w, mut ht, mut depth, mut max, mut tuple) = (None, None, None, None, None);
                loop {
                    let field = h.token().ok_or(ImageError::Header)?;
                    match field {
                        b"WIDTH" => w = Some(h.number()?),
                        b"HEIGHT" => ht = Some(h.number()?),
                        b"DEPTH" => depth = Some(h.number()?),
                        b"MAXVAL" => max = Some(h.number()?),
                        b"TUPLTYPE" => tuple = Some(h.token().ok_or(ImageError::Header)?),
                        b"ENDHDR" => break,
                        _ => return Err(ImageError::Header),
                    }
                }
                let depth = depth.ok_or(ImageError::Header)?;
                match (tuple, depth) {
                    (None | Some(b"RGB"), 3) | (None | Some(b"RGB_ALPHA"), 4) => {}
                    _ => return Err(ImageError::Header),
                }
                let ok = |v: Option<usize>| v.ok_or(ImageError::Header);
                (ok(w)?, ok(ht)?, depth, ok(max)?, h.end()?)
            }
            _ => return Err(ImageError::Format),
        };
        if !(1..=MAX_SIDE).contains(&width) || !(1..=MAX_SIDE).contains(&height) || maxval != 255 {
            return Err(ImageError::Size);
        }
        let data = b.get(start..start + width * height * depth).ok_or(ImageError::Short)?;
        Ok(Image { width, height, alpha: depth == 4, data })
    }

    /// The pixel at (`x`, `y`) as `0xAARRGGBB` (opaque without alpha), or
    /// clear outside the image.
    pub fn pixel(&self, x: usize, y: usize) -> u32 {
        if x >= self.width || y >= self.height {
            return 0;
        }
        let depth = if self.alpha { 4 } else { 3 };
        let p = &self.data[(y * self.width + x) * depth..][..depth];
        let a = if self.alpha { p[3] } else { 0xff };
        u32::from_be_bytes([a, p[0], p[1], p[2]])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{format, vec::Vec};

    fn pam(w: usize, h: usize, tuple: &str, depth: usize) -> Vec<u8> {
        let mut b = format!("P7\nWIDTH {w}\nHEIGHT {h}\nDEPTH {depth}\nMAXVAL 255\nTUPLTYPE {tuple}\nENDHDR\n").into_bytes();
        b.extend((0..w * h * depth).map(|k| k as u8));
        b
    }

    #[test]
    fn reads_pam_with_and_without_alpha() {
        let b = pam(3, 2, "RGB_ALPHA", 4);
        let i = Image::parse(&b).unwrap();
        assert_eq!((i.width, i.height), (3, 2));
        assert_eq!(i.pixel(0, 0), 0x0300_0102);
        assert_eq!(i.pixel(2, 1), 0x1714_1516);
        assert_eq!(i.pixel(3, 0), 0, "outside");
        let b = pam(2, 2, "RGB", 3);
        let i = Image::parse(&b).unwrap();
        assert_eq!(i.pixel(1, 1), 0xff09_0a0b);
    }

    #[test]
    fn reads_ppm_with_comments() {
        let mut b = b"P6 # made by hand\n2 # wide\n1\n255\n".to_vec();
        b.extend([1, 2, 3, 4, 5, 6]);
        let i = Image::parse(&b).unwrap();
        assert_eq!((i.width, i.height, i.pixel(1, 0)), (2, 1, 0xff04_0506));
    }

    #[test]
    fn refuses_what_it_cannot_read() {
        assert_eq!(Image::parse(b"P3 1 1 255\n0 0 0").unwrap_err(), ImageError::Format);
        assert_eq!(Image::parse(b"").unwrap_err(), ImageError::Format);
        assert_eq!(Image::parse(b"P6 1 1 65535\n\0\0\0\0\0\0").unwrap_err(), ImageError::Size);
        assert_eq!(Image::parse(b"P6 0 1 255\n").unwrap_err(), ImageError::Size);
        assert_eq!(Image::parse(b"P6 2 2 255\n\0\0\0").unwrap_err(), ImageError::Short);
        assert_eq!(Image::parse(b"P6 2 2").unwrap_err(), ImageError::Header);
        let mut b = pam(1, 1, "GRAYSCALE", 1);
        assert_eq!(Image::parse(&b).unwrap_err(), ImageError::Header);
        b = pam(1, 1, "RGB_ALPHA", 3);
        assert_eq!(Image::parse(&b).unwrap_err(), ImageError::Header);
        let b = b"P7\nWIDTH 1\nHEIGHT 1\nMAXVAL 255\nENDHDR\n\0\0\0";
        assert_eq!(Image::parse(b).unwrap_err(), ImageError::Header, "no depth");
        let mut b = pam(2, 2, "RGB", 3);
        b.pop();
        assert_eq!(Image::parse(&b).unwrap_err(), ImageError::Short);
    }
}
