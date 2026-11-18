//! A TLS 1.3 client (RFC 8446): what the updater fetches systems over.
//!
//! One of everything: the cipher suite `TLS_AES_128_GCM_SHA256`, X25519 for
//! the key exchange and Ed25519 for the server's signature. The server is
//! not checked against certificate authorities: the client is built with
//! the server's Ed25519 public key and accepts only a certificate holding
//! it (and a `CertificateVerify` that key signed over the handshake), as an
//! updater trusts one update service. Nothing is resumed and no early data
//! is sent; a `HelloRetryRequest` is refused (the client's one key share is
//! X25519, which any server offering it takes).
//!
//! No I/O and no allocation: the caller puts what arrives in with
//! [`Client::receive`], calls [`Client::process`] for what it means (bytes
//! to send, application data, the end), and seals what it sends with
//! [`Client::seal`]. The secrets it needs (the hello's random and the key
//! share's secret) come from the caller.

use crate::crypto::ed25519;
use crate::crypto::gcm::{Gcm, TAG};
use crate::crypto::hkdf;
use crate::crypto::sha2::{Sha256, sha256};
use crate::crypto::x25519;

/// The largest record: 2^14 bytes of plaintext and what protection adds.
pub const RECORD: usize = 5 + (1 << 14) + 256;
/// Input is kept until a record is whole: room for a record short of one
/// byte and as much again arriving (`process` takes each whole record
/// before more is received, so a caller receiving up to a record at a time
/// never finds it full).
const INPUT: usize = 2 * RECORD;
/// Handshake messages are kept until whole, up to this much (a
/// certificate for an Ed25519 key is well under 1 KiB).
const HANDSHAKE: usize = 4096;
/// The most application data a record carries.
pub const MAX_DATA: usize = 1 << 14;

const CHANGE_CIPHER_SPEC: u8 = 20;
const ALERT: u8 = 21;
const HANDSHAKE_RECORD: u8 = 22;
const APPLICATION_DATA: u8 = 23;

const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;
const NEW_SESSION_TICKET: u8 = 4;
const ENCRYPTED_EXTENSIONS: u8 = 8;
const CERTIFICATE: u8 = 11;
const CERTIFICATE_VERIFY: u8 = 15;
const FINISHED: u8 = 20;

const AES_128_GCM_SHA256: u16 = 0x1301;
const X25519: u16 = 0x001d;
const ED25519: u16 = 0x0807;
const TLS13: u16 = 0x0304;

/// The DER of an Ed25519 SubjectPublicKeyInfo up to its key's 32 bytes.
const ED25519_SPKI: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsError {
    /// A record or message that does not parse.
    Malformed,
    /// A message out of turn, or one this client does not do.
    Unexpected,
    /// The server sent this alert.
    Alert(u8),
    /// The server chose something not offered (suite, group, version), or
    /// asked for a retry.
    Unsupported,
    /// The certificate does not hold the server's key.
    WrongKey,
    /// `CertificateVerify` does not verify.
    BadSignature,
    /// The server's `Finished` is wrong.
    BadFinished,
    /// A record that does not decrypt.
    Decrypt,
    /// More than the buffers hold.
    TooBig,
}

/// What [`Client::process`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Nothing whole yet: receive more.
    More,
    /// A record was handled: call again.
    Again,
    /// Send `out[..n]` (the client's `Finished`): the handshake is done.
    Send(usize),
    /// Application data: `app[..n]`.
    Data(usize),
    /// The server closed the connection (close_notify).
    Closed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Start,
    ServerHello,
    EncryptedExtensions,
    Certificate,
    CertificateVerify,
    Finished,
    Connected,
    Closed,
}

/// HKDF-Expand-Label (RFC 8446 7.1).
fn expand_label(secret: &[u8; 32], label: &[u8], context: &[u8], out: &mut [u8]) {
    let len = (out.len() as u16).to_be_bytes();
    let (label_len, context_len) = ([6 + label.len() as u8], [context.len() as u8]);
    hkdf::expand(secret, &[&len, &label_len, b"tls13 ", label, &context_len, context], out);
}

/// Derive-Secret, given the transcript's hash.
fn derive(secret: &[u8; 32], label: &[u8], hash: &[u8; 32]) -> [u8; 32] {
    let mut out = [0; 32];
    expand_label(secret, label, hash, &mut out);
    out
}

/// One direction's record protection.
#[derive(Clone)]
struct Keys {
    gcm: Gcm,
    iv: [u8; 12],
    seq: u64,
}

impl Keys {
    fn new(secret: &[u8; 32]) -> Keys {
        let (mut key, mut iv) = ([0; 16], [0; 12]);
        expand_label(secret, b"key", &[], &mut key);
        expand_label(secret, b"iv", &[], &mut iv);
        Keys { gcm: Gcm::new(&key), iv, seq: 0 }
    }

    fn nonce(&mut self) -> [u8; 12] {
        let mut n = self.iv;
        for (i, b) in self.seq.to_be_bytes().iter().enumerate() {
            n[4 + i] ^= b;
        }
        self.seq += 1;
        n
    }
}

/// Reads big-endian fields from a message, failing past its end.
struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TlsError> {
        if n > self.b.len() {
            return Err(TlsError::Malformed);
        }
        let (a, rest) = self.b.split_at(n);
        self.b = rest;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, TlsError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, TlsError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Result<usize, TlsError> {
        let b = self.take(3)?;
        Ok((b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize)
    }
}

/// A connection's client side.
pub struct Client {
    state: State,
    random: [u8; 32],
    secret: [u8; 32],
    server_key: [u8; 32],
    transcript: Sha256,
    handshake_secret: [u8; 32],
    client_hs: [u8; 32],
    server_hs: [u8; 32],
    read: Option<Keys>,
    write: Option<Keys>,
    input: [u8; INPUT],
    held: usize,
    hs: [u8; HANDSHAKE],
    hs_len: usize,
}

impl Client {
    /// A client that will offer `random` and the X25519 key share of
    /// `secret`, and accept only a server holding `server_key`.
    pub const fn new(random: [u8; 32], secret: [u8; 32], server_key: [u8; 32]) -> Client {
        Client {
            state: State::Start,
            random,
            secret,
            server_key,
            transcript: Sha256::new(),
            handshake_secret: [0; 32],
            client_hs: [0; 32],
            server_hs: [0; 32],
            read: None,
            write: None,
            input: [0; INPUT],
            held: 0,
            hs: [0; HANDSHAKE],
            hs_len: 0,
        }
    }

    /// Starts again for a new connection, in place (the client is too big
    /// to move about on a small stack).
    pub fn reset(&mut self, random: [u8; 32], secret: [u8; 32], server_key: [u8; 32]) {
        self.state = State::Start;
        self.random = random;
        self.secret = secret;
        self.server_key = server_key;
        self.transcript = Sha256::new();
        self.handshake_secret = [0; 32];
        self.client_hs = [0; 32];
        self.server_hs = [0; 32];
        self.read = None;
        self.write = None;
        self.held = 0;
        self.hs_len = 0;
    }

    /// Whether the handshake is done, and application data may go both
    /// ways.
    pub fn connected(&self) -> bool {
        self.state == State::Connected
    }

    /// The ClientHello record, into `out` (at least 128 bytes): its
    /// length.
    pub fn hello(&mut self, out: &mut [u8]) -> usize {
        let share = x25519::public(&self.secret);
        let mut m = [0u8; 128];
        let mut n = 0;
        fn put(m: &mut [u8; 128], n: &mut usize, b: &[u8]) {
            m[*n..*n + b.len()].copy_from_slice(b);
            *n += b.len();
        }
        put(&mut m, &mut n, &[CLIENT_HELLO, 0, 0, 0]);
        put(&mut m, &mut n, &0x0303u16.to_be_bytes());
        put(&mut m, &mut n, &self.random);
        put(&mut m, &mut n, &[0]); // no legacy session ID
        put(&mut m, &mut n, &[0, 2]);
        put(&mut m, &mut n, &AES_128_GCM_SHA256.to_be_bytes());
        put(&mut m, &mut n, &[1, 0]); // the null compression method alone
        let ext_at = n;
        put(&mut m, &mut n, &[0, 0]);
        // supported_versions: TLS 1.3 only.
        put(&mut m, &mut n, &[0x00, 0x2b, 0, 3, 2]);
        put(&mut m, &mut n, &TLS13.to_be_bytes());
        // supported_groups: X25519.
        put(&mut m, &mut n, &[0x00, 0x0a, 0, 4, 0, 2]);
        put(&mut m, &mut n, &X25519.to_be_bytes());
        // signature_algorithms: Ed25519.
        put(&mut m, &mut n, &[0x00, 0x0d, 0, 4, 0, 2]);
        put(&mut m, &mut n, &ED25519.to_be_bytes());
        // key_share: one X25519 share.
        put(&mut m, &mut n, &[0x00, 0x33, 0, 38, 0, 36]);
        put(&mut m, &mut n, &X25519.to_be_bytes());
        put(&mut m, &mut n, &[0, 32]);
        put(&mut m, &mut n, &share);
        let ext_len = (n - ext_at - 2) as u16;
        m[ext_at..ext_at + 2].copy_from_slice(&ext_len.to_be_bytes());
        let body = (n - 4) as u32;
        m[1..4].copy_from_slice(&body.to_be_bytes()[1..]);
        self.transcript.update(&m[..n]);
        out[..5].copy_from_slice(&[HANDSHAKE_RECORD, 3, 1, (n >> 8) as u8, n as u8]);
        out[5..5 + n].copy_from_slice(&m[..n]);
        self.state = State::ServerHello;
        5 + n
    }

    /// Takes what arrived (as much as there is room for): how much it
    /// took.
    pub fn receive(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(INPUT - self.held);
        self.input[self.held..self.held + n].copy_from_slice(&data[..n]);
        self.held += n;
        n
    }

    /// Room for more input.
    pub fn room(&self) -> usize {
        INPUT - self.held
    }

    /// Seals `data` (at most [`MAX_DATA`] bytes) as an application data
    /// record into `out` (`data.len() + 22` bytes): its length.
    pub fn seal(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, TlsError> {
        if self.state != State::Connected {
            return Err(TlsError::Unexpected);
        }
        self.protect(APPLICATION_DATA, data, out)
    }

    fn protect(&mut self, kind: u8, data: &[u8], out: &mut [u8]) -> Result<usize, TlsError> {
        let keys = self.write.as_mut().ok_or(TlsError::Unexpected)?;
        let len = data.len() + 1 + TAG;
        if data.len() > MAX_DATA || out.len() < 5 + len {
            return Err(TlsError::TooBig);
        }
        let header = [APPLICATION_DATA, 3, 3, (len >> 8) as u8, len as u8];
        out[..5].copy_from_slice(&header);
        out[5..5 + data.len()].copy_from_slice(data);
        out[5 + data.len()] = kind;
        let nonce = keys.nonce();
        let tag = keys.gcm.seal(&nonce, &header, &mut out[5..5 + data.len() + 1]);
        out[5 + len - TAG..5 + len].copy_from_slice(&tag);
        Ok(5 + len)
    }

    /// Handles what has arrived: a whole handshake message kept from an
    /// earlier record, or else one whole record. `out` takes what is to be
    /// sent (128 bytes do), `app` application data (up to [`MAX_DATA`]).
    pub fn process(&mut self, out: &mut [u8], app: &mut [u8]) -> Result<Step, TlsError> {
        if let Some(step) = self.handshake_message(out)? {
            return Ok(step);
        }
        if self.state == State::Closed {
            return Ok(Step::Closed);
        }
        if self.held < 5 {
            return Ok(Step::More);
        }
        let len = (self.input[3] as usize) << 8 | self.input[4] as usize;
        if 5 + len > RECORD {
            return Err(TlsError::TooBig);
        }
        if self.held < 5 + len {
            return Ok(Step::More);
        }
        let kind = self.input[0];
        let header: [u8; 5] = self.input[..5].try_into().unwrap();
        let step = match kind {
            // Sent for middleboxes' sake; meaningless.
            CHANGE_CIPHER_SPEC if self.state != State::Connected => Ok(Step::Again),
            ALERT if self.read.is_none() => Err(TlsError::Alert(*self.input.get(6).unwrap_or(&0))),
            HANDSHAKE_RECORD if self.state == State::ServerHello => {
                let body = &self.input[5..5 + len];
                if self.hs_len + len > HANDSHAKE {
                    return Err(TlsError::TooBig);
                }
                self.hs[self.hs_len..self.hs_len + len].copy_from_slice(body);
                self.hs_len += len;
                Ok(Step::Again)
            }
            APPLICATION_DATA if self.read.is_some() && len > TAG => {
                let keys = self.read.as_mut().unwrap();
                let nonce = keys.nonce();
                let tag: [u8; TAG] = self.input[5 + len - TAG..5 + len].try_into().unwrap();
                if !keys.gcm.open(&nonce, &header, &mut self.input[5..5 + len - TAG], &tag) {
                    return Err(TlsError::Decrypt);
                }
                // The inner plaintext: content, its type, zeros.
                let inner = &self.input[5..5 + len - TAG];
                let end = inner.iter().rposition(|&b| b != 0).ok_or(TlsError::Malformed)?;
                let (content, inner_kind) = (&inner[..end], inner[end]);
                match inner_kind {
                    HANDSHAKE_RECORD => {
                        if self.hs_len + content.len() > HANDSHAKE {
                            return Err(TlsError::TooBig);
                        }
                        self.hs[self.hs_len..self.hs_len + content.len()].copy_from_slice(content);
                        self.hs_len += content.len();
                        Ok(Step::Again)
                    }
                    APPLICATION_DATA if self.state == State::Connected => {
                        app[..content.len()].copy_from_slice(content);
                        Ok(Step::Data(content.len()))
                    }
                    ALERT if content.len() == 2 && content[1] == 0 => {
                        self.state = State::Closed;
                        Ok(Step::Closed)
                    }
                    ALERT if content.len() == 2 => Err(TlsError::Alert(content[1])),
                    _ => Err(TlsError::Unexpected),
                }
            }
            _ => Err(TlsError::Unexpected),
        };
        self.input.copy_within(5 + len..self.held, 0);
        self.held -= 5 + len;
        step
    }

    /// Handles the first handshake message kept, if it is whole.
    fn handshake_message(&mut self, out: &mut [u8]) -> Result<Option<Step>, TlsError> {
        if self.hs_len < 4 {
            return Ok(None);
        }
        let len = (self.hs[1] as usize) << 16 | (self.hs[2] as usize) << 8 | self.hs[3] as usize;
        if 4 + len > HANDSHAKE {
            return Err(TlsError::TooBig);
        }
        if self.hs_len < 4 + len {
            return Ok(None);
        }
        let mut msg = [0u8; HANDSHAKE];
        msg[..4 + len].copy_from_slice(&self.hs[..4 + len]);
        self.hs.copy_within(4 + len..self.hs_len, 0);
        self.hs_len -= 4 + len;
        let msg = &msg[..4 + len];
        let step = match (self.state, msg[0]) {
            (State::ServerHello, SERVER_HELLO) => self.server_hello(msg)?,
            (State::EncryptedExtensions, ENCRYPTED_EXTENSIONS) => {
                self.transcript.update(msg);
                self.state = State::Certificate;
                Step::Again
            }
            (State::Certificate, CERTIFICATE) => self.certificate(msg)?,
            (State::CertificateVerify, CERTIFICATE_VERIFY) => self.certificate_verify(msg)?,
            (State::Finished, FINISHED) => self.finished(msg, out)?,
            // Tickets for resumption, which this client does not do.
            (State::Connected, NEW_SESSION_TICKET) => Step::Again,
            _ => return Err(TlsError::Unexpected),
        };
        Ok(Some(step))
    }

    fn server_hello(&mut self, msg: &[u8]) -> Result<Step, TlsError> {
        let mut r = Reader { b: &msg[4..] };
        r.u16()?;
        let random = r.take(32)?;
        // SHA-256("HelloRetryRequest"): a retry, which needs a share this
        // client does not have.
        if random == sha256(b"HelloRetryRequest") {
            return Err(TlsError::Unsupported);
        }
        let sid = r.u8()? as usize;
        r.take(sid)?;
        if r.u16()? != AES_128_GCM_SHA256 || r.u8()? != 0 {
            return Err(TlsError::Unsupported);
        }
        let ext_len = r.u16()? as usize;
        let mut ext = Reader { b: r.take(ext_len)? };
        let (mut version, mut share) = (false, None);
        while !ext.b.is_empty() {
            let kind = ext.u16()?;
            let len = ext.u16()? as usize;
            let mut data = Reader { b: ext.take(len)? };
            match kind {
                0x002b => version = data.u16()? == TLS13,
                0x0033 => {
                    if data.u16()? != X25519 || data.u16()? != 32 {
                        return Err(TlsError::Unsupported);
                    }
                    share = Some(<[u8; 32]>::try_from(data.take(32)?).unwrap());
                }
                _ => {}
            }
        }
        let share = share.filter(|_| version).ok_or(TlsError::Unsupported)?;
        self.transcript.update(msg);
        let shared = x25519::x25519(&self.secret, &share);
        if shared == [0; 32] {
            return Err(TlsError::Malformed);
        }
        let early = hkdf::extract(&[0; 32], &[0; 32]);
        let salt = derive(&early, b"derived", &sha256(&[]));
        self.handshake_secret = hkdf::extract(&salt, &shared);
        let hash = self.transcript.clone().finish();
        self.client_hs = derive(&self.handshake_secret, b"c hs traffic", &hash);
        self.server_hs = derive(&self.handshake_secret, b"s hs traffic", &hash);
        self.read = Some(Keys::new(&self.server_hs));
        self.write = Some(Keys::new(&self.client_hs));
        self.state = State::EncryptedExtensions;
        Ok(Step::Again)
    }

    fn certificate(&mut self, msg: &[u8]) -> Result<Step, TlsError> {
        let mut r = Reader { b: &msg[4..] };
        let context = r.u8()? as usize;
        r.take(context)?;
        let list = r.u24()?;
        let mut list = Reader { b: r.take(list)? };
        let len = list.u24()?;
        let cert = list.take(len)?;
        let key = cert
            .windows(ED25519_SPKI.len() + 32)
            .find(|w| w[..ED25519_SPKI.len()] == ED25519_SPKI)
            .map(|w| &w[ED25519_SPKI.len()..])
            .ok_or(TlsError::WrongKey)?;
        if key != self.server_key {
            return Err(TlsError::WrongKey);
        }
        self.transcript.update(msg);
        self.state = State::CertificateVerify;
        Ok(Step::Again)
    }

    fn certificate_verify(&mut self, msg: &[u8]) -> Result<Step, TlsError> {
        let mut r = Reader { b: &msg[4..] };
        if r.u16()? != ED25519 || r.u16()? != 64 {
            return Err(TlsError::BadSignature);
        }
        let signature: [u8; 64] = r.take(64)?.try_into().unwrap();
        let hash = self.transcript.clone().finish();
        let signed: [&[u8]; 4] = [&[0x20; 64], b"TLS 1.3, server CertificateVerify", &[0], &hash];
        if !ed25519::verify(&self.server_key, &signed, &signature) {
            return Err(TlsError::BadSignature);
        }
        self.transcript.update(msg);
        self.state = State::Finished;
        Ok(Step::Again)
    }

    fn finished(&mut self, msg: &[u8], out: &mut [u8]) -> Result<Step, TlsError> {
        let finished_key = |secret: &[u8; 32]| {
            let mut k = [0; 32];
            expand_label(secret, b"finished", &[], &mut k);
            k
        };
        let want = hkdf::hmac_sha256(&finished_key(&self.server_hs), &[&self.transcript.clone().finish()]);
        if msg.len() != 4 + 32 || want.iter().zip(&msg[4..]).fold(0, |d, (a, b)| d | (a ^ b)) != 0 {
            return Err(TlsError::BadFinished);
        }
        self.transcript.update(msg);
        let hash = self.transcript.clone().finish();
        let master = hkdf::extract(&derive(&self.handshake_secret, b"derived", &sha256(&[])), &[0; 32]);
        let client_ap = derive(&master, b"c ap traffic", &hash);
        let server_ap = derive(&master, b"s ap traffic", &hash);
        // The client's Finished, under its handshake keys.
        let verify = hkdf::hmac_sha256(&finished_key(&self.client_hs), &[&hash]);
        let mut fin = [0u8; 36];
        fin[0] = FINISHED;
        fin[3] = 32;
        fin[4..].copy_from_slice(&verify);
        let n = self.protect(HANDSHAKE_RECORD, &fin, out)?;
        self.read = Some(Keys::new(&server_ap));
        self.write = Some(Keys::new(&client_ap));
        // Nothing secret is kept that the traffic keys do not need.
        self.secret = [0; 32];
        self.handshake_secret = [0; 32];
        self.state = State::Connected;
        Ok(Step::Send(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> [u8; 32] {
        let mut b = [0; 32];
        for i in 0..32 {
            b[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        b
    }

    /// RFC 8448's key schedule: the early secret with no PSK, and the salt
    /// derived from it for the handshake secret.
    #[test]
    fn key_schedule_rfc8448() {
        let early = hkdf::extract(&[0; 32], &[0; 32]);
        assert_eq!(early, h("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"));
        assert_eq!(derive(&early, b"derived", &sha256(&[])), h("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"));
    }

    /// The hello parses as one: a handshake record holding a ClientHello
    /// whose lengths add up, offering exactly what the client does.
    #[test]
    fn hello_is_well_formed() {
        let mut c = Client::new([7; 32], [9; 32], [0; 32]);
        let mut out = [0u8; 256];
        let n = c.hello(&mut out);
        assert_eq!(out[0], HANDSHAKE_RECORD);
        assert_eq!(((out[3] as usize) << 8 | out[4] as usize) + 5, n);
        assert_eq!(out[5], CLIENT_HELLO);
        let body = (out[6] as usize) << 16 | (out[7] as usize) << 8 | out[8] as usize;
        assert_eq!(body + 9, n);
        let share = x25519::public(&[9; 32]);
        assert_eq!(&out[n - 32..n], &share);
    }

    extern crate std;
    use std::boxed::Box;
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::vec::Vec;

    /// A rustls server with a self-signed Ed25519 certificate, and the
    /// certificate's public key.
    fn server() -> (rustls::ServerConnection, [u8; 32]) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = rcgen::CertificateParams::new(std::vec!["updates.test".into()]).unwrap().self_signed(&key).unwrap();
        let public: [u8; 32] = key.public_key_raw().try_into().unwrap();
        let private = rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(std::vec![cert.der().clone()], private)
            .unwrap();
        (rustls::ServerConnection::new(Arc::new(config)).unwrap(), public)
    }

    /// What the server has to send.
    fn from_server(s: &mut rustls::ServerConnection) -> Vec<u8> {
        let mut out = Vec::new();
        while s.wants_write() {
            s.write_tls(&mut out).unwrap();
        }
        out
    }

    /// Feeds the client `bytes` a few at a time (as TCP may deliver them)
    /// and runs it: what it sends and the application data it got.
    fn run(c: &mut Client, bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, bool), TlsError> {
        let (mut sent, mut data, mut closed) = (Vec::new(), Vec::new(), false);
        let mut out = [0u8; 256];
        let mut app = std::vec![0u8; MAX_DATA];
        for piece in bytes.chunks(97) {
            let mut piece = piece;
            while !piece.is_empty() {
                let n = c.receive(piece);
                piece = &piece[n..];
                loop {
                    match c.process(&mut out, &mut app)? {
                        Step::More => break,
                        Step::Again => {}
                        Step::Send(n) => sent.extend_from_slice(&out[..n]),
                        Step::Data(n) => data.extend_from_slice(&app[..n]),
                        Step::Closed => {
                            closed = true;
                            break;
                        }
                    }
                }
            }
        }
        Ok((sent, data, closed))
    }

    /// A whole connection with rustls: the handshake, a request, a
    /// response of several records, and close_notify.
    #[test]
    fn talks_to_rustls() {
        let (mut s, public) = server();
        let mut c = Box::new(Client::new([1; 32], [2; 32], public));
        let mut hello = [0u8; 256];
        let n = c.hello(&mut hello);
        s.read_tls(&mut &hello[..n]).unwrap();
        s.process_new_packets().unwrap();
        let (fin, _, _) = run(&mut c, &from_server(&mut s)).unwrap();
        assert!(c.connected());
        s.read_tls(&mut &fin[..]).unwrap();
        s.process_new_packets().unwrap();
        assert!(!s.is_handshaking());

        let mut rec = std::vec![0u8; 64];
        const REQUEST: &[u8] = b"GET /system?have=2 HTTP/1.1\r\n\r\n";
        let n = c.seal(REQUEST, &mut rec).unwrap();
        s.read_tls(&mut &rec[..n]).unwrap();
        s.process_new_packets().unwrap();
        let mut got = [0u8; 64];
        let n = s.reader().read(&mut got).unwrap();
        assert_eq!(&got[..n], REQUEST);

        let body: Vec<u8> = (0..40_000u32).map(|i| (i * 7 + i / 300) as u8).collect();
        s.writer().write_all(&body).unwrap();
        s.send_close_notify();
        let (_, data, closed) = run(&mut c, &from_server(&mut s)).unwrap();
        assert_eq!(data, body);
        assert!(closed);
    }

    /// A server with another key is refused at its certificate, and a
    /// record changed on the way at its tag.
    #[test]
    fn refuses_the_wrong_server_and_changed_records() {
        let (mut s, _) = server();
        let mut c = Box::new(Client::new([1; 32], [2; 32], [0x42; 32]));
        let mut hello = [0u8; 256];
        let n = c.hello(&mut hello);
        s.read_tls(&mut &hello[..n]).unwrap();
        s.process_new_packets().unwrap();
        assert_eq!(run(&mut c, &from_server(&mut s)).unwrap_err(), TlsError::WrongKey);

        let (mut s, public) = server();
        let mut c = Box::new(Client::new([1; 32], [2; 32], public));
        let n = c.hello(&mut hello);
        s.read_tls(&mut &hello[..n]).unwrap();
        s.process_new_packets().unwrap();
        let mut flight = from_server(&mut s);
        let last = flight.len() - 3;
        flight[last] ^= 1;
        assert_eq!(run(&mut c, &flight).unwrap_err(), TlsError::Decrypt);
    }

    /// A server that answers with garbage, or out of turn, gets an error,
    /// never a panic.
    #[test]
    fn garbage_is_refused() {
        let mut c = Client::new([7; 32], [9; 32], [0; 32]);
        let mut out = [0u8; 256];
        let mut app = [0u8; 64];
        c.hello(&mut out);
        c.receive(&[22, 3, 3, 0, 6, 2, 0, 0, 2, 3, 3]);
        assert_eq!(c.process(&mut out, &mut app), Ok(Step::Again));
        assert_eq!(c.process(&mut out, &mut app), Err(TlsError::Malformed));
        let mut c = Client::new([7; 32], [9; 32], [0; 32]);
        c.hello(&mut out);
        c.receive(&[23, 3, 3, 0, 20]);
        c.receive(&[0; 20]);
        assert_eq!(c.process(&mut out, &mut app), Err(TlsError::Unexpected));
        let mut c = Client::new([7; 32], [9; 32], [0; 32]);
        c.hello(&mut out);
        c.receive(&[21, 3, 3, 0, 2, 2, 40]);
        assert_eq!(c.process(&mut out, &mut app), Err(TlsError::Alert(40)));
    }
}
