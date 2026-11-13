//! Each primitive against its published test vectors, then the handshake
//! and CCMP end to end, and what each must refuse.

use crate::aes::{Aes128, ccm_open, ccm_seal, key_unwrap, key_wrap};
use crate::ccmp::{self, Refused};
use crate::handshake::{Authenticator, Error, Gtk, RSNE_PSK_CCMP, Supplicant, ptk};
use crate::sha1::{hmac_sha1, pbkdf2_sha1, prf, psk, sha1};

fn hex<const N: usize>(s: &str) -> [u8; N] {
    let s = s.as_bytes();
    assert_eq!(s.len(), 2 * N, "length");
    let d = |c: u8| (c as char).to_digit(16).unwrap() as u8;
    core::array::from_fn(|i| d(s[2 * i]) << 4 | d(s[2 * i + 1]))
}

#[test]
fn sha1_vectors() {
    assert_eq!(sha1(b"abc"), hex("a9993e364706816aba3e25717850c26c9cd0d89d"));
    assert_eq!(sha1(b""), hex("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    // FIPS 180's two-block message.
    assert_eq!(
        sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        hex("84983e441c3bd26ebaae4aa1f95129e5e54670f1")
    );
}

#[test]
fn hmac_sha1_vectors() {
    // RFC 2202, test cases 1 and 2, and 6 (a key longer than a block).
    assert_eq!(hmac_sha1(&[0x0b; 20], &[b"Hi There"]), hex("b617318655057264e28bc0b6fb378c8ef146be00"));
    assert_eq!(
        hmac_sha1(b"Jefe", &[b"what do ya ", b"want for nothing?"]),
        hex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
    );
    assert_eq!(
        hmac_sha1(&[0xaa; 80], &[b"Test Using Larger Than Block-Size Key - Hash Key First"]),
        hex("aa4ae5e15272d00e95705637ce8a3b55ed402112")
    );
}

#[test]
fn pbkdf2_vectors() {
    // RFC 6070.
    for (rounds, want) in [
        (1, "0c60c80f961f0e71f3a9b524af6012062fe037a6"),
        (2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
        (4096, "4b007901b765489abead49d926f721d065a429c1"),
    ] {
        let mut out = [0u8; 20];
        pbkdf2_sha1(b"password", b"salt", rounds, &mut out);
        assert_eq!(out, hex::<20>(want), "{rounds} rounds");
    }
}

#[test]
fn passphrase_to_pmk() {
    // IEEE 802.11 Annex J.4.
    assert_eq!(
        psk(b"password", b"IEEE"),
        hex("f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e")
    );
    assert_eq!(
        psk(b"ThisIsAPassword", b"ThisIsASSID"),
        hex("0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af")
    );
}

#[test]
fn prf_vector() {
    // IEEE 802.11 Annex J.3, test case 1.
    let mut out = [0u8; 64];
    prf(&[0x0b; 20], b"prefix", &[b"Hi There"], &mut out);
    assert_eq!(
        out,
        hex::<64>(
            "bcd4c650b30b9684951829e0d75f9d54b862175ed9f00606e17d8da35402ffee\
             75df78c3d31e0f889f012120c0862beb67753e7439ae242edb8373698356cf5a"
        )
    );
}

#[test]
fn aes_vector() {
    // FIPS 197, Appendix C.1.
    let aes = Aes128::new(&hex("000102030405060708090a0b0c0d0e0f"));
    let mut b = hex("00112233445566778899aabbccddeeff");
    aes.encrypt(&mut b);
    assert_eq!(b, hex("69c4e0d86a7b0430d8cdb78070b4c55a"));
    aes.decrypt(&mut b);
    assert_eq!(b, hex("00112233445566778899aabbccddeeff"));
}

#[test]
fn key_wrap_vector() {
    // RFC 3394, 4.1.
    let kek = hex("000102030405060708090a0b0c0d0e0f");
    let data: [u8; 16] = hex("00112233445566778899aabbccddeeff");
    let mut wrapped = [0u8; 24];
    key_wrap(&kek, &data, &mut wrapped);
    assert_eq!(wrapped, hex("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"));
    let mut back = [0u8; 16];
    assert!(key_unwrap(&kek, &wrapped, &mut back));
    assert_eq!(back, data);
    wrapped[5] ^= 1;
    assert!(!key_unwrap(&kek, &wrapped, &mut back), "a changed byte fails the check");
}

#[test]
fn ccm_vector() {
    // RFC 3610, packet vector 1: 8 bytes of AAD, 23 of payload, 8-byte tag.
    let aes = Aes128::new(&hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"));
    let nonce = hex("00000003020100a0a1a2a3a4a5");
    let aad: [u8; 8] = core::array::from_fn(|i| i as u8);
    let mut data: [u8; 23] = core::array::from_fn(|i| 8 + i as u8);
    let tag = ccm_seal(&aes, &nonce, &aad, &mut data);
    assert_eq!(data, hex::<23>("588c979a61c663d2f066d0c2c0f989806d5f6b61dac384"));
    assert_eq!(tag, hex("17e8d12cfdf926e0"));
    assert!(ccm_open(&aes, &nonce, &aad, &mut data, &tag));
    assert_eq!(data, core::array::from_fn::<u8, 23, _>(|i| 8 + i as u8));
    let mut bad = tag;
    bad[0] ^= 1;
    let mut again = data;
    ccm_seal(&aes, &nonce, &aad, &mut again);
    assert!(!ccm_open(&aes, &nonce, &aad, &mut again, &bad));
    assert_eq!(again, hex::<23>("588c979a61c663d2f066d0c2c0f989806d5f6b61dac384"), "left encrypted");
}

const AA: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
const SPA: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
const GTK: Gtk = Gtk { index: 1, key: [0x77; 16] };

fn pair(pass: &[u8]) -> (Authenticator, Supplicant) {
    let ap = Authenticator::new(psk(b"correct horse", b"superior"), AA, SPA, [0xa1; 32], &RSNE_PSK_CCMP, GTK);
    let sta = Supplicant::new(psk(pass, b"superior"), SPA, AA, [0x5e; 32], &RSNE_PSK_CCMP, &RSNE_PSK_CCMP);
    (ap, sta)
}

#[test]
fn the_handshake_gives_both_sides_the_same_keys() {
    let (mut ap, mut sta) = pair(b"correct horse");
    let m1 = ap.start();
    let m2 = sta.receive(m1.bytes()).unwrap();
    let m3 = ap.receive(m2.bytes()).unwrap().expect("message 3");
    assert_eq!(sta.keys(), None, "no keys before message 3");
    let m4 = sta.receive(m3.bytes()).unwrap();
    assert!(matches!(ap.receive(m4.bytes()), Ok(None)));
    let keys = sta.keys().expect("keys");
    let want = ptk(&psk(b"correct horse", b"superior"), &AA, &SPA, &[0xa1; 32], &[0x5e; 32]);
    assert_eq!(keys.tk, want.tk);
    assert_eq!(ap.tk(), Some(want.tk));
    assert_eq!(keys.gtk, GTK);
}

#[test]
fn a_wrong_passphrase_fails_at_message_2() {
    let (mut ap, mut sta) = pair(b"wrong horse");
    let m2 = sta.receive(ap.start().bytes()).unwrap();
    assert_eq!(ap.receive(m2.bytes()).err(), Some(Error::Mic));
    assert_eq!(ap.tk(), None);
}

#[test]
fn forged_and_replayed_frames_are_refused() {
    let (mut ap, mut sta) = pair(b"correct horse");
    let m1 = ap.start();
    let m2 = sta.receive(m1.bytes()).unwrap();
    let m3 = ap.receive(m2.bytes()).unwrap().unwrap();
    // A changed byte in message 3 breaks its MIC.
    let mut forged = [0u8; 256];
    let n = m3.bytes().len();
    forged[..n].copy_from_slice(m3.bytes());
    forged[n - 1] ^= 1;
    assert_eq!(sta.receive(&forged[..n]).err(), Some(Error::Mic));
    // The real one is taken; then neither it nor message 1 again.
    sta.receive(m3.bytes()).unwrap();
    assert_eq!(sta.receive(m3.bytes()).err(), Some(Error::Replay));
    assert_eq!(sta.receive(m1.bytes()).err(), Some(Error::Replay));
}

#[test]
fn a_downgraded_rsn_element_is_refused() {
    // The station saw a different RSN element advertised (say, the access
    // point's real one with TKIP), so message 3's does not match.
    let mut tkip = RSNE_PSK_CCMP;
    tkip[13] = 2;
    let mut ap = Authenticator::new(psk(b"correct horse", b"superior"), AA, SPA, [0xa1; 32], &RSNE_PSK_CCMP, GTK);
    let mut sta = Supplicant::new(psk(b"correct horse", b"superior"), SPA, AA, [0x5e; 32], &RSNE_PSK_CCMP, &tkip);
    let m2 = sta.receive(ap.start().bytes()).unwrap();
    let m3 = ap.receive(m2.bytes()).unwrap().unwrap();
    assert_eq!(sta.receive(m3.bytes()).err(), Some(Error::Rsne));
    assert_eq!(sta.keys(), None);
}

/// A QoS data frame from the station to the access point: frame control,
/// duration, three addresses, sequence control, QoS control.
fn qos_header() -> [u8; 26] {
    let mut h = [0u8; 26];
    h[0] = 0x88; // data, QoS
    h[1] = 0x01; // to the DS
    h[4..10].copy_from_slice(&AA);
    h[10..16].copy_from_slice(&SPA);
    h[16..22].copy_from_slice(&AA);
    h[22..24].copy_from_slice(&0x0120u16.to_le_bytes());
    h[24] = 5; // TID 5
    h
}

#[test]
fn ccmp_frames_round_trip_and_refuse_forgery_and_replay() {
    let tk = [0x3c; 16];
    let body = *b"\xaa\xaa\x03\x00\x00\x00\x08\x00an IPv4 packet";
    let mut f = [0u8; 128];
    let n = ccmp::seal(&tk, 7, 0, &qos_header(), &body, &mut f).unwrap();
    assert_eq!(n, 26 + 8 + body.len() + 8);
    assert_ne!(&f[34..34 + body.len()], &body[..], "the body is encrypted");
    let mut copy = f;
    let (range, pn) = ccmp::open(&tk, &mut copy[..n], Some(6)).unwrap();
    assert_eq!((&copy[range], pn), (&body[..], 7));
    // A retry bit set in flight is masked out of the MIC; the TID is not.
    let mut retried = f;
    retried[1] |= 0x08;
    assert!(ccmp::open(&tk, &mut retried[..n], None).is_ok());
    let mut other_tid = f;
    other_tid[24] = 6;
    assert_eq!(ccmp::open(&tk, &mut other_tid[..n], None).err(), Some(Refused::Forged));
    let mut flipped = f;
    flipped[40] ^= 0x80;
    assert_eq!(ccmp::open(&tk, &mut flipped[..n], None).err(), Some(Refused::Forged));
    let (mut other_key, mut replayed) = (f, f);
    assert_eq!(ccmp::open(&[0x3d; 16], &mut other_key[..n], None).err(), Some(Refused::Forged));
    assert_eq!(ccmp::open(&tk, &mut replayed[..n], Some(7)).err(), Some(Refused::Replayed));
}
