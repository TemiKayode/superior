//! Each primitive against its published test vectors, then the handshake
//! and CCMP end to end, and what each must refuse.

use crate::aes::{Aes128, ccm_open, ccm_seal, key_unwrap, key_wrap};
use crate::ccmp::{self, Refused};
use crate::handshake::{Akm, Authenticator, Error, Gtk, RSNE_PSK_CCMP, Supplicant, ptk};
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
    let ap = Authenticator::new(Akm::Psk, psk(b"correct horse", b"superior"), AA, SPA, [0xa1; 32], &RSNE_PSK_CCMP, GTK);
    let sta = Supplicant::new(Akm::Psk, psk(pass, b"superior"), SPA, AA, [0x5e; 32], &RSNE_PSK_CCMP, &RSNE_PSK_CCMP);
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
    let mut ap = Authenticator::new(Akm::Psk, psk(b"correct horse", b"superior"), AA, SPA, [0xa1; 32], &RSNE_PSK_CCMP, GTK);
    let mut sta = Supplicant::new(Akm::Psk, psk(b"correct horse", b"superior"), SPA, AA, [0x5e; 32], &RSNE_PSK_CCMP, &tkip);
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

mod air {
    //! A station and an access point on one simulated channel.

    use crate::ap::{AccessPoint, Peer};
    use crate::handshake::Gtk;
    use crate::station::{Link, Station};
    extern crate std;
    use std::vec::Vec;

    pub const STA: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
    pub const BSSID: [u8; 6] = [0x02, 0x57, 0x49, 0x46, 0x49, 0x01];

    pub struct Air {
        pub sta: Station,
        pub ap: AccessPoint,
        pub to_ap: Vec<Vec<u8>>,
        pub to_sta: Vec<Vec<u8>>,
        pub sta_up: Vec<Vec<u8>>,
        pub ap_up: Vec<Vec<u8>>,
        pub now: u64,
        /// Whether to lose every other frame to the access point.
        pub lossy: bool,
        lost: bool,
        /// Whether to strip the RSN extension element from what the
        /// access point announces (a downgrade attempt).
        pub strip_rsnx: bool,
    }

    impl Air {
        pub fn new(ap_pass: &[u8]) -> Air {
            Air::offering(ap_pass, true, false)
        }

        /// With an access point offering WPA2-PSK and/or WPA3-SAE.
        pub fn offering(ap_pass: &[u8], psk: bool, sae: bool) -> Air {
            let gtk = Gtk { index: 1, key: [0x47; 16] };
            Air {
                sta: Station::new(STA),
                ap: AccessPoint::new(BSSID, b"superior", ap_pass, gtk, [9; 32]).offering(psk, sae),
                to_ap: Vec::new(),
                to_sta: Vec::new(),
                sta_up: Vec::new(),
                ap_up: Vec::new(),
                now: 0,
                lossy: false,
                lost: false,
                strip_rsnx: false,
            }
        }

        /// With a WPA3-only access point that takes hash-to-element.
        pub fn h2e(ap_pass: &[u8]) -> Air {
            let gtk = Gtk { index: 1, key: [0x47; 16] };
            let ap = AccessPoint::new(BSSID, b"superior", ap_pass, gtk, [9; 32]).offering(false, true).hash_to_element();
            Air { ap, ..Air::offering(ap_pass, false, true) }
        }

        /// A beacon or probe response without its RSN extension element.
        fn strip(f: &[u8]) -> Vec<u8> {
            let mut out = f[..crate::frame::HEADER + 12].to_vec();
            for (id, body) in crate::frame::elements(&f[crate::frame::HEADER + 12..]) {
                if id != crate::frame::RSNX {
                    out.extend([id, body.len() as u8]);
                    out.extend(body);
                }
            }
            out
        }

        /// Runs the channel for `ms` milliseconds, 10 at a time.
        pub fn run(&mut self, ms: u64) {
            for _ in 0..ms / 10 {
                self.now += 10;
                let mut out = Vec::new();
                self.sta.poll(self.now, &mut |f| out.push(f.to_vec()));
                self.ap.poll(self.now, &mut |f| self.to_sta.push(f.to_vec()));
                self.to_ap.extend(out);
                for f in core::mem::take(&mut self.to_ap) {
                    if self.lossy {
                        self.lost = !self.lost;
                        if self.lost {
                            continue;
                        }
                    }
                    let (mut back, mut up) = (Vec::new(), Vec::new());
                    self.ap.receive(&f, self.now, &mut |r| back.push(r.to_vec()), &mut |e| up.push(e.to_vec()));
                    self.to_sta.extend(back);
                    self.ap_up.extend(up);
                }
                for mut f in core::mem::take(&mut self.to_sta) {
                    if self.strip_rsnx && matches!(f[0], crate::frame::BEACON | crate::frame::PROBE_RESP) {
                        f = Air::strip(&f);
                    }
                    let (mut back, mut up) = (Vec::new(), Vec::new());
                    self.sta.receive(&f, -40, self.now, &mut |r| back.push(r.to_vec()), &mut |e| up.push(e.to_vec()));
                    self.to_ap.extend(back);
                    self.sta_up.extend(up);
                }
            }
        }

        pub fn joined(&self) -> bool {
            self.sta.link() == Link::Up && self.ap.peer() == Peer::Up
        }
    }
}

fn ethernet_frame(da: [u8; 6], sa: [u8; 6], payload: &[u8]) -> ([u8; 1514], usize) {
    let mut e = [0u8; 1514];
    let n = crate::frame::to_ethernet(&mut e, &da, &sa, 0x0800, payload).unwrap();
    (e, n)
}

#[test]
fn a_station_finds_joins_and_carries_frames_both_ways() {
    use crate::station::Link;
    let mut air = air::Air::new(b"correct horse");
    assert_eq!(air.sta.link(), Link::Idle);
    assert!(air.sta.join(b"superior", b"correct horse", [7; 32], 0));
    air.run(200);
    assert!(air.joined(), "joined in 200 ms: {:?} / {:?}", air.sta.link(), air.ap.peer());
    assert_eq!(air.sta.bssid(), air::BSSID);
    // Up: the station's frame reaches the access point, sealed.
    let (e, n) = ethernet_frame(air::BSSID, air::STA, b"to the gateway");
    let mut f = [0u8; crate::frame::MAX];
    let len = air.sta.send(&e[..n], &mut f).unwrap();
    assert!(!f[..len].windows(14).any(|w| w == b"to the gateway"), "sealed");
    air.to_ap.push(f[..len].to_vec());
    // And the access point's, one to the station and one broadcast (the
    // group key's).
    for da in [air::STA, [0xff; 6]] {
        let (e, n) = ethernet_frame(da, air::BSSID, b"from the gateway");
        let len = air.ap.send(&e[..n], &mut f).unwrap();
        air.to_sta.push(f[..len].to_vec());
    }
    air.run(10);
    assert_eq!(air.ap_up.len(), 1);
    assert_eq!(&air.ap_up[0][..], &e[..n]);
    assert_eq!(air.sta_up.len(), 2);
    assert_eq!(&air.sta_up[0][14..], b"from the gateway");
    assert_eq!(&air.sta_up[1][..6], &[0xff; 6]);
    // The same frame again is a replay.
    let replay = air.to_sta.len();
    let (e, n) = ethernet_frame(air::STA, air::BSSID, b"once");
    let len = air.ap.send(&e[..n], &mut f).unwrap();
    air.to_sta.push(f[..len].to_vec());
    air.to_sta.push(f[..len].to_vec());
    air.run(10);
    assert_eq!(replay, 0);
    assert_eq!(air.sta_up.len(), 3, "taken once");
    assert_eq!(air.sta.refused, 1);
}

#[test]
fn joining_survives_losing_every_other_frame() {
    let mut air = air::Air::new(b"correct horse");
    air.lossy = true;
    air.sta.join(b"superior", b"correct horse", [7; 32], 0);
    air.run(10_000);
    assert!(air.joined(), "{:?} / {:?}", air.sta.link(), air.ap.peer());
}

#[test]
fn a_wrong_passphrase_never_brings_the_link_up() {
    use crate::station::Link;
    let mut air = air::Air::new(b"another horse");
    air.sta.join(b"superior", b"correct horse", [7; 32], 0);
    air.run(10_000);
    assert_ne!(air.sta.link(), Link::Up);
    assert!(air.ap.refused > 0, "message 2's MIC refused");
    let (e, n) = ethernet_frame(air::BSSID, air::STA, b"x");
    assert_eq!(air.sta.send(&e[..n], &mut [0u8; 128]), None, "nothing goes out unkeyed");
}

#[test]
fn another_ssid_is_not_joined() {
    use crate::station::Link;
    let mut air = air::Air::new(b"correct horse");
    air.sta.join(b"elsewhere", b"correct horse", [7; 32], 0);
    air.run(2000);
    assert_eq!(air.sta.link(), Link::Scanning);
    assert!(!air.sta.join(b"superior", b"short", [7; 32], 0), "a passphrase under 8 characters");
}

#[test]
fn a_message_3_sent_again_is_answered_but_its_keys_not_reinstalled() {
    let (mut ap, mut sta) = pair(b"correct horse");
    let m2 = sta.receive(ap.start().bytes()).unwrap();
    let m3 = ap.receive(m2.bytes()).unwrap().unwrap();
    let _lost_m4 = sta.receive(m3.bytes()).unwrap();
    let keys = sta.keys();
    let again = ap.retry().expect("message 3 again");
    let m4 = sta.receive(again.bytes()).unwrap();
    assert_eq!(sta.keys(), keys);
    assert!(matches!(ap.receive(m4.bytes()), Ok(None)));
    assert!(ap.tk().is_some());
    assert!(ap.retry().is_none(), "nothing to send once done");
    // And no new handshake over keys in use.
    assert_eq!(sta.receive(ap.start().bytes()).err(), Some(Error::State));
}

#[test]
fn keys_are_renewed_pairwise_then_group_and_resends_install_nothing() {
    let (mut ap, mut sta) = pair(b"correct horse");
    let m2 = sta.receive(ap.start().bytes()).unwrap();
    let m3 = ap.receive(m2.bytes()).unwrap().unwrap();
    let m4 = sta.receive(m3.bytes()).unwrap();
    assert!(matches!(ap.receive(m4.bytes()), Ok(None)));
    let first = sta.keys().unwrap();
    assert_eq!(sta.installs(), 1);
    // A rekeying needs a fresh nonce given first.
    assert!(sta.needs_nonce());
    sta.renew([0x5f; 32]);
    let m1 = ap.rekey([0xa2; 32]).expect("rekeying starts");
    assert!(ap.rekey([0xa3; 32]).is_none(), "one at a time");
    let m2 = sta.receive(m1.bytes()).unwrap();
    assert_eq!(sta.keys(), Some(first), "the old keys carry on until message 3");
    let m3 = ap.receive(m2.bytes()).unwrap().unwrap();
    assert!(ap.pending_tk().is_some());
    let _lost_m4 = sta.receive(m3.bytes()).unwrap();
    let renewed = sta.keys().unwrap();
    assert_ne!(renewed.tk, first.tk);
    assert_eq!(renewed.gtk, GTK);
    assert_eq!(sta.installs(), 2);
    let m4 = sta.receive(ap.retry().unwrap().bytes()).unwrap();
    assert_eq!(sta.installs(), 2, "message 3 again installs nothing");
    assert!(matches!(ap.receive(m4.bytes()), Ok(None)));
    assert_eq!(ap.tk(), Some(renewed.tk));
    assert!(!ap.rekeying());
    // Without a new nonce, no further pairwise rekeying is taken.
    assert_eq!(sta.receive(ap.rekey([0xa4; 32]).unwrap().bytes()).err(), Some(Error::State));
    let (mut ap, mut sta) = keyed_pair();
    // The group key: one message, confirmed.
    let new = Gtk { index: 2, key: [0x78; 16] };
    let g1 = ap.rekey_group(new).unwrap();
    let g2 = sta.receive(g1.bytes()).unwrap();
    assert_eq!(sta.keys().unwrap().gtk, new);
    let installs = sta.installs();
    // Its confirmation lost: sent again, answered, not installed again.
    let g2 = {
        let _ = g2;
        sta.receive(ap.retry().unwrap().bytes()).unwrap()
    };
    assert_eq!(sta.installs(), installs);
    assert_eq!(ap.gtk(), GTK, "the old group key until confirmed");
    assert!(matches!(ap.receive(g2.bytes()), Ok(None)));
    assert_eq!(ap.gtk(), new);
    assert!(ap.retry().is_none());
    // A forged group key message is refused.
    let mut forged = ap.rekey_group(Gtk { index: 1, key: [0x79; 16] }).unwrap().bytes().to_vec();
    forged[120] ^= 1;
    assert_eq!(sta.receive(&forged).err(), Some(Error::Mic));
    assert_eq!(sta.keys().unwrap().gtk, new);
}

/// An authenticator and supplicant keyed with each other.
fn keyed_pair() -> (Authenticator, Supplicant) {
    let (mut ap, mut sta) = pair(b"correct horse");
    let m2 = sta.receive(ap.start().bytes()).unwrap();
    let m3 = ap.receive(m2.bytes()).unwrap().unwrap();
    let m4 = sta.receive(m3.bytes()).unwrap();
    assert!(matches!(ap.receive(m4.bytes()), Ok(None)));
    (ap, sta)
}

/// Sends one frame each way (the access point's alternately to the station
/// and broadcast) and runs the channel 10 ms; returns the frames sent.
fn exchange(air: &mut air::Air, k: usize) -> usize {
    let mut f = [0u8; crate::frame::MAX];
    let mut sent = 0;
    let (e, n) = ethernet_frame(air::BSSID, air::STA, &[k as u8; 40]);
    if let Some(len) = air.sta.send(&e[..n], &mut f) {
        air.to_ap.push(f[..len].to_vec());
        sent += 1;
    }
    let da = if k % 2 == 0 { air::STA } else { [0xff; 6] };
    let (e, n) = ethernet_frame(da, air::BSSID, &[k as u8; 40]);
    if let Some(len) = air.ap.send(&e[..n], &mut f) {
        air.to_sta.push(f[..len].to_vec());
        sent += 1;
    }
    air.run(10);
    sent
}

#[test]
fn rekeying_while_frames_flow_loses_none() {
    use crate::handshake::Gtk;
    let mut air = air::Air::new(b"correct horse");
    air.sta.join(b"superior", b"correct horse", [7; 32], 0);
    air.run(200);
    assert!(air.joined());
    let mut sent = 0;
    for k in 0..60 {
        let now = air.now;
        match k {
            10 | 40 => assert!(air.ap.rekey(now, &mut |f| air.to_sta.push(f.to_vec()))),
            25 => assert!(air.ap.rekey_group(Gtk { index: 2, key: [0x48; 16] }, now, &mut |f| air.to_sta.push(f.to_vec()))),
            50 => assert!(air.ap.rekey_group(Gtk { index: 1, key: [0x49; 16] }, now, &mut |f| air.to_sta.push(f.to_vec()))),
            _ => {}
        }
        sent += exchange(&mut air, k);
    }
    air.run(50);
    assert_eq!((air.sta.rekeys, air.sta.group_rekeys), (2, 2));
    assert_eq!((air.ap.rekeys, air.ap.group_rekeys), (2, 2));
    assert!(!air.ap.rekeying());
    assert_eq!((air.sta.refused, air.ap.refused), (0, 0));
    assert_eq!(air.sta_up.len() + air.ap_up.len(), sent, "every frame delivered");
    assert_eq!(sent, 120);
}

#[test]
fn rekeying_survives_losing_every_other_frame() {
    use crate::handshake::Gtk;
    let mut air = air::Air::new(b"correct horse");
    air.sta.join(b"superior", b"correct horse", [7; 32], 0);
    air.run(200);
    assert!(air.joined());
    air.lossy = true;
    let now = air.now;
    assert!(air.ap.rekey(now, &mut |f| air.to_sta.push(f.to_vec())));
    air.run(5000);
    let now = air.now;
    assert!(air.ap.rekey_group(Gtk { index: 2, key: [0x48; 16] }, now, &mut |f| air.to_sta.push(f.to_vec())));
    air.run(5000);
    assert_eq!((air.ap.rekeys, air.ap.group_rekeys), (1, 1));
    assert_eq!((air.sta.rekeys, air.sta.group_rekeys), (1, 1));
    // Frames still flow both ways under the new keys.
    air.lossy = false;
    let before = air.sta_up.len() + air.ap_up.len();
    let sent = (0..4).map(|k| exchange(&mut air, k)).sum::<usize>();
    assert_eq!(air.sta_up.len() + air.ap_up.len() - before, sent);
    assert_eq!(sent, 8);
}

/// A beacon from `bssid` for `ssid` on `channel`, with `capability` and
/// RSN element `rsne` (if any).
fn beacon(bssid: [u8; 6], ssid: &[u8], capability: u16, rsne: Option<&[u8]>, channel: u8) -> std::vec::Vec<u8> {
    use crate::frame::*;
    let mut f = [0u8; 256];
    let mut n = header(&mut f, BEACON, 0, &BROADCAST, &bssid, &bssid, 1);
    f[n + 10..n + 12].copy_from_slice(&capability.to_le_bytes());
    n += 12;
    n = element(&mut f, n, SSID, ssid);
    n = element(&mut f, n, DS_PARAMS, &[channel]);
    if let Some(e) = rsne {
        f[n..n + e.len()].copy_from_slice(e);
        n += e.len();
    }
    f[..n].to_vec()
}

extern crate std;

/// RSN elements: SAE only (with management frame protection required),
/// PSK and SAE, 802.1X, and PSK with TKIP alone.
const RSNE_SAE: [u8; 22] = [0x30, 20, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 8, 0xc0, 0];
const RSNE_MIXED: [u8; 26] =
    [0x30, 24, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 2, 0, 0x00, 0x0f, 0xac, 2, 0x00, 0x0f, 0xac, 8, 0x80, 0];
const RSNE_8021X: [u8; 22] = [0x30, 20, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 1, 0, 0];
const RSNE_TKIP: [u8; 22] = [0x30, 20, 1, 0, 0x00, 0x0f, 0xac, 2, 1, 0, 0x00, 0x0f, 0xac, 2, 1, 0, 0x00, 0x0f, 0xac, 2, 0, 0];

#[test]
fn security_is_read_from_the_rsn_element() {
    use crate::station::Security;
    assert_eq!(Security::of(0x0001, None), Security::Open);
    assert_eq!(Security::of(0x0011, None), Security::Other, "privacy without RSN: WEP");
    assert_eq!(Security::of(0x0011, Some(&RSNE_PSK_CCMP)), Security::Wpa2Psk);
    assert_eq!(Security::of(0x0011, Some(&RSNE_SAE)), Security::Wpa3Sae);
    assert_eq!(Security::of(0x0011, Some(&RSNE_MIXED)), Security::Wpa2Wpa3);
    assert_eq!(Security::of(0x0011, Some(&RSNE_8021X)), Security::Enterprise);
    assert_eq!(Security::of(0x0011, Some(&RSNE_TKIP)), Security::Other);
    assert_eq!(Security::of(0x0011, Some(&RSNE_SAE[..9])), Security::Other, "cut short");
}

#[test]
fn a_survey_lists_every_network_heard_strongest_first() {
    use crate::station::{Link, Security};
    let mut air = air::Air::new(b"correct horse");
    let mut out = std::vec::Vec::new();
    assert!(air.sta.survey(0, &mut |f| out.push(f.to_vec())));
    assert!(!air.sta.survey(0, &mut |_| {}), "one at a time");
    air.to_ap.extend(out); // a wildcard probe: the access point answers
    let guest = [0x02, 0, 0, 0, 0, 0x02];
    let sae = [0x02, 0, 0, 0, 0, 0x03];
    let mut ignore = |_: &[u8]| {};
    let mut nothing = |_: &[u8]| {};
    air.sta.receive(&beacon(guest, b"guest", 0x0001, None, 11), -71, 0, &mut ignore, &mut nothing);
    air.sta.receive(&beacon(sae, b"neighbour", 0x0011, Some(&RSNE_SAE), 1), -85, 0, &mut ignore, &mut nothing);
    air.sta.receive(&beacon(sae, b"neighbour", 0x0011, Some(&RSNE_SAE), 1), -78, 0, &mut ignore, &mut nothing);
    air.run(200);
    assert!(air.sta.surveying());
    air.run(300);
    assert!(!air.sta.surveying());
    let found: std::vec::Vec<_> = air.sta.networks().map(|n| (n.bssid, n.ssid().to_vec(), n.signal, n.channel, n.security)).collect();
    assert_eq!(
        found,
        [
            (air::BSSID, b"superior".to_vec(), -40, 6, Security::Wpa2Psk),
            (guest, b"guest".to_vec(), -71, 11, Security::Open),
            (sae, b"neighbour".to_vec(), -78, 1, Security::Wpa3Sae),
        ]
    );
    assert_eq!(air.sta.link(), Link::Idle, "surveying joins nothing");
    // Surveying while linked leaves the link up and frames flowing.
    air.sta.join(b"superior", b"correct horse", [7; 32], air.now);
    air.run(200);
    assert!(air.joined());
    let now = air.now;
    let mut out = std::vec::Vec::new();
    assert!(air.sta.survey(now, &mut |f| out.push(f.to_vec())));
    air.to_ap.extend(out);
    let sent = (0..50).map(|k| exchange(&mut air, k)).sum::<usize>();
    assert!(air.joined() && !air.sta.surveying());
    assert_eq!(air.sta.networks().count(), 1);
    assert_eq!(air.sta_up.len() + air.ap_up.len(), sent);
}

fn unhex<const L: usize>(s: &str) -> [u8; L] {
    let s: std::vec::Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    assert_eq!(s.len(), 2 * L);
    core::array::from_fn(|i| u8::from_str_radix(core::str::from_utf8(&s[2 * i..2 * i + 2]).unwrap(), 16).unwrap())
}

#[test]
fn hmac_sha256_and_cmac_match_their_rfcs() {
    use crate::aes::cmac;
    use crate::sha256::hmac_sha256;
    // RFC 4231, test case 2.
    assert_eq!(
        hmac_sha256(b"Jefe", &[b"what do ya ", b"want for nothing?"]),
        unhex::<32>("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    );
    // RFC 4493: the empty message, and one block.
    let key = unhex::<16>("2b7e151628aed2a6abf7158809cf4f3c");
    assert_eq!(cmac(&key, &[]), unhex::<16>("bb1d6929e95937287fa37d129b756746"));
    assert_eq!(cmac(&key, &unhex::<16>("6bc1bee22e409f96e93d7e117393172a")), unhex::<16>("070a16b46b4d4144f79bdd9dd04a287c"));
    // 40 bytes (a partial last block).
    let m40 = unhex::<40>("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");
    assert_eq!(cmac(&key, &m40), unhex::<16>("dfa66747de9ae63030ca32611497c827"));
}

#[test]
fn p256_points_add_up() {
    use crate::p256::{Affine, N, Point, from_be};
    let g = Affine::generator();
    assert!(g.on_curve());
    let gp = g.point();
    let two = gp.double().affine().unwrap();
    assert_eq!(two.x, from_be(&unhex("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978")));
    assert_eq!(two.y, from_be(&unhex("07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1")));
    let three = gp.mul(&[3, 0, 0, 0]).affine().unwrap();
    assert_eq!(three.x, from_be(&unhex("5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c")));
    assert_eq!(three.y, from_be(&unhex("8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032")));
    assert_eq!(gp.add(&gp).affine(), Some(two), "adding a point to itself doubles it");
    assert!(gp.mul(&N).is_infinity(), "n·G is the point at infinity");
    let n1 = [N[0] - 1, N[1], N[2], N[3]];
    assert_eq!(gp.mul(&n1).affine(), Some(g.neg()));
    assert_eq!(gp.add(&g.neg().point()), Point::INFINITY);
    // (a·G)·b = (b·G)·a.
    let a = from_be(&[0x5a; 32]);
    let b = from_be(&[0xc3; 32]);
    let ab = gp.mul(&a).mul(&b).affine().unwrap();
    assert_eq!(gp.mul(&b).mul(&a).affine().unwrap(), ab);
    assert!(ab.on_curve());
    assert_eq!(Affine::decode(&ab.encode()), Some(ab));
    let mut off = ab.encode();
    off[63] ^= 1;
    assert_eq!(Affine::decode(&off), None, "off the curve");
}

/// SAE's 64 random bytes: `rand` all `r`, `mask` all `m`.
fn random(r: u8, m: u8) -> [u8; 64] {
    core::array::from_fn(|i| if i < 32 { r } else { m })
}

#[test]
fn sae_peers_reach_the_same_pmk_and_refuse_what_they_should() {
    use crate::sae::{Error as SaeError, Sae};
    let (a, b) = ([0x82, 0x7b, 0x91, 0x9d, 0xd4, 0xb9], [0x1e, 0xec, 0x49, 0xea, 0x64, 0x88]);
    let mut sta = Sae::new(b"mekmitasdigoat", &a, &b, &random(0x21, 0x43)).unwrap();
    let r = random(0x65, 0x87);
    let mut ap = Sae::new(b"mekmitasdigoat", &b, &a, &r).unwrap();
    assert_eq!(sta.receive_confirm(&[0; 34]).err(), Some(SaeError::State));
    let c_sta = sta.receive_commit(&ap.commit()).unwrap();
    let c_ap = ap.receive_commit(&sta.commit()).unwrap();
    assert_eq!(sta.pmk(), None, "not before the confirm");
    ap.receive_confirm(&c_sta).unwrap();
    sta.receive_confirm(&c_ap).unwrap();
    assert_eq!(sta.pmk(), ap.pmk());
    assert!(sta.pmk().is_some());
    assert_eq!(sta.pmkid(), ap.pmkid());
    // Another password: the confirm does not hold.
    let mut wrong = Sae::new(b"another password", &b, &a, &r).unwrap();
    let mut sta2 = Sae::new(b"mekmitasdigoat", &a, &b, &random(0x21, 0x43)).unwrap();
    let c2 = sta2.receive_commit(&wrong.commit()).unwrap();
    let cw = wrong.receive_commit(&sta2.commit()).unwrap();
    assert_eq!(wrong.receive_confirm(&c2).err(), Some(SaeError::Confirm));
    assert_eq!(sta2.receive_confirm(&cw).err(), Some(SaeError::Confirm));
    // Our own commit reflected, a bad group, scalar or element.
    let own = sta2.commit();
    assert_eq!(sta2.receive_commit(&own).err(), Some(SaeError::Reflection));
    let mut bad = ap.commit();
    bad[0] = 20;
    assert_eq!(sta2.receive_commit(&bad).err(), Some(SaeError::Group));
    let mut bad = ap.commit();
    bad[2..34].fill(0);
    assert_eq!(sta2.receive_commit(&bad).err(), Some(SaeError::Scalar));
    let mut bad = ap.commit();
    bad[97] ^= 1;
    assert_eq!(sta2.receive_commit(&bad).err(), Some(SaeError::Element));
    assert_eq!(sta2.receive_commit(&ap.commit()[..50]).err(), Some(SaeError::Malformed));
}

#[test]
fn the_4_way_handshake_under_sae_uses_cmac_and_delivers_the_igtk() {
    use crate::handshake::{Igtk, RSNE_SAE};
    let pmk = [0x3a; 32];
    let igtk = Igtk { index: 4, key: [0x91; 16], pn: 0x0102_0304_0506 };
    let mut ap = Authenticator::new(Akm::Sae, pmk, AA, SPA, [0xa1; 32], &RSNE_SAE, GTK).with_igtk(igtk);
    let mut sta = Supplicant::new(Akm::Sae, pmk, SPA, AA, [0x5e; 32], &RSNE_SAE, &RSNE_SAE);
    let m1 = ap.start();
    assert_eq!(m1.bytes()[6] & 7, 0, "key descriptor version 0: defined by the AKM");
    let m2 = sta.receive(m1.bytes()).unwrap();
    let m3 = ap.receive(m2.bytes()).unwrap().unwrap();
    let m4 = sta.receive(m3.bytes()).unwrap();
    assert!(matches!(ap.receive(m4.bytes()), Ok(None)));
    let keys = sta.keys().unwrap();
    assert_eq!(Some(keys.tk), ap.tk());
    assert_eq!(keys.igtk, Some(igtk));
    assert_ne!(keys.tk, crate::handshake::ptk(&pmk, &AA, &SPA, &[0xa1; 32], &[0x5e; 32]).tk, "not WPA2's PTK");
    // A WPA2 station's frames are refused under SAE, and message 3
    // without an IGTK too.
    let mut psk_sta = Supplicant::new(Akm::Psk, pmk, SPA, AA, [0x5e; 32], &RSNE_PSK_CCMP, &RSNE_SAE);
    let mut ap = Authenticator::new(Akm::Sae, pmk, AA, SPA, [0xa1; 32], &RSNE_SAE, GTK);
    assert_eq!(psk_sta.receive(ap.start().bytes()).err(), Some(Error::Malformed));
    let mut sta = Supplicant::new(Akm::Sae, pmk, SPA, AA, [0x5e; 32], &RSNE_SAE, &RSNE_SAE);
    let m2 = sta.receive(ap.start().bytes()).unwrap();
    let m3 = ap.receive(m2.bytes()).unwrap().unwrap();
    assert_eq!(sta.receive(m3.bytes()).err(), Some(Error::KeyData));
}

#[test]
fn a_station_joins_wpa3_by_sae_and_carries_frames() {
    let mut air = air::Air::offering(b"correct horse", false, true);
    air.sta.join(b"superior", b"correct horse", [7; 32], 0);
    air.run(500);
    assert!(air.joined(), "{:?} / {:?}", air.sta.link(), air.ap.peer());
    assert_eq!((air.sta.akm(), air.ap.akm()), (Akm::Sae, Akm::Sae));
    let sent = (0..10).map(|k| exchange(&mut air, k)).sum::<usize>();
    assert_eq!(air.sta_up.len() + air.ap_up.len(), sent);
    assert_eq!(sent, 20);
    // Rekeying works the same under SAE.
    let now = air.now;
    assert!(air.ap.rekey(now, &mut |f| air.to_sta.push(f.to_vec())));
    air.run(50);
    assert_eq!((air.sta.rekeys, air.ap.rekeys), (1, 1));
}

#[test]
fn a_transition_mode_access_point_is_joined_by_sae() {
    let mut air = air::Air::offering(b"correct horse", true, true);
    air.sta.join(b"superior", b"correct horse", [7; 32], 0);
    air.run(500);
    assert!(air.joined());
    assert_eq!(air.ap.akm(), Akm::Sae);
}

#[test]
fn h2e_s_password_element_and_each_mapped_point_are_on_the_curve() {
    use crate::p256::{FIELD, curve_rhs};
    let on_curve = |p: &crate::p256::Affine| { let y = FIELD.to_mont(&p.y); FIELD.mul(&y, &y) == curve_rhs(&p.x) };
    for k in 0..16u64 {
        assert!(on_curve(&crate::sae::sswu(&[k.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1, k, 0, 0])), "u = {k}");
    }
    let pt = crate::sae::pt(b"superior", b"correct horse").unwrap();
    assert!(on_curve(&pt));
    // Per network: another SSID or password, another PT.
    assert_ne!(crate::sae::pt(b"superior2", b"correct horse"), Some(pt));
    assert_ne!(crate::sae::pt(b"superior", b"correct horsf"), Some(pt));
}

#[test]
fn sae_by_hash_to_element_agrees_and_differs_from_hunting_and_pecking() {
    use crate::sae::{Sae, pt};
    let (a, b) = ([2u8, 0, 0, 0, 0, 1], [2u8, 0, 0, 0, 0, 2]);
    let t = pt(b"superior", b"correct horse").unwrap();
    let mut x = Sae::new_h2e(&t, &a, &b, &[0x11; 64]).unwrap();
    let mut y = Sae::new_h2e(&t, &b, &a, &[0x22; 64]).unwrap();
    let cx = x.receive_commit(&y.commit()).unwrap();
    let cy = y.receive_commit(&x.commit()).unwrap();
    x.receive_confirm(&cy).unwrap();
    y.receive_confirm(&cx).unwrap();
    assert!(x.pmk().is_some() && x.pmk() == y.pmk());
    // Hunting and pecking with the same password and draws: another PWE.
    let mut z = Sae::new(b"correct horse", &b, &a, &[0x22; 64]).unwrap();
    let mut x2 = Sae::new_h2e(&t, &a, &b, &[0x11; 64]).unwrap();
    let cz = z.receive_commit(&x2.commit()).unwrap();
    x2.receive_commit(&z.commit()).unwrap();
    assert!(x2.receive_confirm(&cz).is_err(), "methods do not mix");
}

#[test]
fn a_station_joins_by_hash_to_element_when_the_network_offers_it() {
    let mut air = air::Air::h2e(b"correct horse");
    air.sta.join(b"superior", b"correct horse", [7; 32], 0);
    air.run(500);
    assert!(air.joined(), "{:?} / {:?}", air.sta.link(), air.ap.peer());
    assert!(air.sta.hash_to_element() && air.ap.station_used_h2e());
    assert_eq!(exchange(&mut air, 1), 2);
    // Without it offered: hunting and pecking, as before.
    let mut air = air::Air::offering(b"correct horse", false, true);
    air.sta.join(b"superior", b"correct horse", [7; 32], 0);
    air.run(500);
    assert!(air.joined() && !air.sta.hash_to_element() && !air.ap.station_used_h2e());
}

#[test]
fn stripping_the_h2e_advertisement_is_caught_as_a_downgrade() {
    use crate::station::Link;
    let mut air = air::Air::h2e(b"correct horse");
    air.strip_rsnx = true;
    air.sta.join(b"superior", b"correct horse", [7; 32], 0);
    air.run(3000);
    assert!(!air.sta.hash_to_element(), "the station heard no H2E");
    assert_ne!(air.sta.link(), Link::Up, "never keyed by hunting and pecking");
    assert!(air.ap.refused > 0, "the association refused");
}

#[test]
fn joining_by_sae_survives_losing_every_other_frame() {
    let mut air = air::Air::offering(b"correct horse", false, true);
    air.lossy = true;
    air.sta.join(b"superior", b"correct horse", [7; 32], 0);
    air.run(15_000);
    assert!(air.joined(), "{:?} / {:?}", air.sta.link(), air.ap.peer());
}

#[test]
fn a_wrong_password_fails_sae_s_confirm() {
    use crate::station::Link;
    let mut air = air::Air::offering(b"another horse", false, true);
    air.sta.join(b"superior", b"correct horse", [7; 32], 0);
    air.run(5000);
    assert_ne!(air.sta.link(), Link::Up);
    assert_ne!(air.sta.link(), Link::Associating, "never past authentication");
    assert!(air.ap.refused > 0, "the station's confirm refused");
}

/// A deauthentication from the access point to the station, unprotected
/// (as anyone in range can forge one).
fn forged_deauth() -> std::vec::Vec<u8> {
    let mut f = [0u8; 26];
    let n = crate::frame::header(&mut f, crate::frame::DEAUTH, 0, &air::STA, &air::BSSID, &air::BSSID, 9);
    f[n..n + 2].copy_from_slice(&[7, 0]);
    f.to_vec()
}

#[test]
fn under_wpa3_only_a_sealed_deauthentication_is_obeyed() {
    use crate::station::Link;
    let mut air = air::Air::offering(b"correct horse", false, true);
    air.sta.join(b"superior", b"correct horse", [7; 32], 0);
    air.run(500);
    assert!(air.joined());
    air.to_sta.push(forged_deauth());
    air.run(10);
    assert_eq!(air.sta.link(), Link::Up, "a forged deauthentication is ignored");
    assert_eq!(air.sta.refused, 1);
    air.ap.deauth(&mut |f| air.to_sta.push(f.to_vec()));
    air.run(10);
    assert_ne!(air.sta.link(), Link::Up, "the access point's own, sealed, is obeyed");
    // Under WPA2 there is no protection: a forged one knocks it off.
    let mut air = air::Air::new(b"correct horse");
    air.sta.join(b"superior", b"correct horse", [7; 32], 0);
    air.run(200);
    assert!(air.joined());
    air.to_sta.push(forged_deauth());
    air.run(10);
    assert_ne!(air.sta.link(), Link::Up);
}

/// A deauthentication to every station, from the access point, with no
/// MMIE (or with `mmie`, as given).
fn group_deauth(mmie: Option<(&crate::handshake::Igtk, u64)>) -> std::vec::Vec<u8> {
    let mut f = [0u8; 64];
    let mut n = crate::frame::header(&mut f, crate::frame::DEAUTH, 0, &crate::frame::BROADCAST, &air::BSSID, &air::BSSID, 9);
    f[n..n + 2].copy_from_slice(&[7, 0]);
    n += 2;
    if let Some((igtk, ipn)) = mmie {
        n = crate::bip::protect(igtk, ipn, &mut f, n).unwrap();
    }
    f[..n].to_vec()
}

#[test]
fn bip_protects_round_trips_and_refuses_forgery_and_replay() {
    use crate::bip::{protect, verify, Refused, MMIE_LEN};
    use crate::handshake::Igtk;
    let igtk = Igtk { index: 4, key: [0x5a; 16], pn: 0 };
    let f = group_deauth(Some((&igtk, 7)));
    assert_eq!(f.len(), 24 + 2 + MMIE_LEN);
    assert_eq!(verify(&igtk, &f, None), Ok(7));
    assert_eq!(verify(&igtk, &f, Some(6)), Ok(7));
    assert_eq!(verify(&igtk, &f, Some(7)), Err(Refused::Replayed));
    assert_eq!(verify(&igtk, &group_deauth(None), None), Err(Refused::Unprotected));
    let other = Igtk { index: 5, key: [0x5a; 16], pn: 0 };
    assert_eq!(verify(&other, &f, None), Err(Refused::WrongKey));
    let wrong = Igtk { index: 4, key: [0x5b; 16], pn: 0 };
    assert_eq!(verify(&wrong, &f, None), Err(Refused::BadMic));
    // Any change to the body or the addresses breaks the MIC; a retry bit
    // set on the way does not.
    let mut changed = f.clone();
    changed[24] ^= 1;
    assert_eq!(verify(&igtk, &changed, None), Err(Refused::BadMic));
    let mut changed = f.clone();
    changed[10] ^= 1;
    assert_eq!(verify(&igtk, &changed, None), Err(Refused::BadMic));
    let mut retried = f.clone();
    retried[1] |= 0x08;
    assert_eq!(verify(&igtk, &retried, None), Ok(7));
    // Too long a body is not protected.
    let mut big = [0u8; 400];
    assert_eq!(protect(&igtk, 1, &mut big, 24 + 300), None);
}

#[test]
fn under_wpa3_only_a_deauthentication_to_all_under_bip_is_obeyed() {
    use crate::station::Link;
    let mut air = air::Air::offering(b"correct horse", false, true);
    air.sta.join(b"superior", b"correct horse", [7; 32], 0);
    air.run(500);
    assert!(air.joined());
    let igtk = air.ap.igtk();
    // No MMIE; one under a key the station does not have; one replaying
    // a packet number already used: all ignored.
    air.to_sta.push(group_deauth(None));
    air.to_sta.push(group_deauth(Some((&crate::handshake::Igtk { index: 4, key: [1; 16], pn: 0 }, 99))));
    air.run(10);
    assert_eq!(air.sta.link(), Link::Up, "forged deauthentications to all are ignored");
    assert_eq!(air.sta.ignored_group_deauths, 2);
    assert_eq!(air.sta.last_bip_refusal, Some(crate::bip::Refused::BadMic));
    // The access point's own, under BIP, is obeyed.
    air.ap.deauth_all(&mut |f| air.to_sta.push(f.to_vec()));
    let sent = air.to_sta.last().unwrap().clone();
    air.run(10);
    assert_ne!(air.sta.link(), Link::Up, "the access point's own, under BIP, is obeyed");
    // The station joins again; the same frame replayed is then refused.
    air.run(500);
    assert!(air.joined());
    let mut replay = sent.clone();
    replay[22] ^= 0x10; // another sequence number: the MMIE still matches
    air.to_sta.push(replay);
    air.run(10);
    assert_eq!(air.sta.link(), Link::Up, "a replayed deauthentication to all is ignored");
    assert_eq!(air.sta.last_bip_refusal, Some(crate::bip::Refused::Replayed));
    // Message 3 told the rejoined station the packet number reached.
    assert_eq!(air.ap.ipn(), 1);
    let _ = igtk;
}
