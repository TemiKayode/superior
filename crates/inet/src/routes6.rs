//! IPv6 routes, as router advertisements give them (RFC 4861, RFC 4191):
//! the prefixes that are on the link, the default routers with their
//! preferences and lifetimes, and more specific routes through a named
//! router. [`Routes::next_hop`] picks where a packet goes: the
//! destination itself if it is on the link, else the router of the
//! longest matching route, else the best default router. A router that
//! does not answer neighbour discovery is passed over for a while, so
//! traffic moves to another if there is one.
//!
//! Times are in whatever unit the caller's clock counts.

/// Routers, on-link prefixes and specific routes kept, each.
pub const ENTRIES: usize = 4;

/// A router's preference (RFC 4191): the two bits of its advertisement.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Preference {
    Low,
    Medium,
    High,
}

impl Preference {
    /// From the two-bit field: 01 high, 11 low, 00 medium; 10 is
    /// reserved and read as medium.
    pub const fn from_bits(bits: u8) -> Preference {
        match bits & 3 {
            1 => Preference::High,
            3 => Preference::Low,
            _ => Preference::Medium,
        }
    }
}

#[derive(Clone, Copy)]
struct Router {
    addr: u128,
    until: u64,
    preference: Preference,
    /// Passed over until then: it did not answer.
    silent_until: u64,
    /// Order learned in: the older of two equals is kept in use.
    learned: u64,
}

#[derive(Clone, Copy)]
struct Prefix {
    prefix: u128,
    len: u8,
    until: u64,
}

#[derive(Clone, Copy)]
struct Route {
    to: Prefix,
    router: u128,
    preference: Preference,
}

#[derive(Clone, Copy)]
pub struct Routes {
    routers: [Option<Router>; ENTRIES],
    on_link: [Option<Prefix>; ENTRIES],
    routes: [Option<Route>; ENTRIES],
    learned: u64,
}

const fn mask(len: u8) -> u128 {
    if len == 0 { 0 } else { !0u128 << (128 - if len > 128 { 128 } else { len } as u32) }
}

impl Prefix {
    fn covers(&self, a: u128, now: u64) -> bool {
        now < self.until && a & mask(self.len) == self.prefix
    }
}

impl Default for Routes {
    fn default() -> Self {
        Self::new()
    }
}

impl Routes {
    pub const fn new() -> Routes {
        Routes {
            routers: [None; ENTRIES],
            on_link: [None; ENTRIES],
            routes: [None; ENTRIES],
            learned: 0,
        }
    }

    /// The slot for a new entry among `entries`: an empty or expired one,
    /// else the one `worst` ranks lowest.
    fn slot<T: Copy>(
        entries: &[Option<T>; ENTRIES],
        expired: impl Fn(&T) -> bool,
        worst: impl Fn(&T) -> (Preference, u64),
    ) -> usize {
        if let Some(i) = entries.iter().position(|e| e.is_none_or(|e| expired(&e))) {
            return i;
        }
        let mut at = 0;
        for i in 1..ENTRIES {
            if worst(&entries[i].unwrap()) < worst(&entries[at].unwrap()) {
                at = i;
            }
        }
        at
    }

    /// A router advertisement from `router`: a default router for
    /// `lifetime` from `now`, or no longer one if that is 0.
    pub fn advert(&mut self, router: u128, lifetime: u64, preference: Preference, now: u64) {
        let known = self.routers.iter().position(|r| r.is_some_and(|r| r.addr == router));
        if lifetime == 0 {
            if let Some(i) = known {
                self.routers[i] = None;
            }
            return;
        }
        let until = now.saturating_add(lifetime);
        if let Some(i) = known {
            let r = self.routers[i].as_mut().unwrap();
            (r.until, r.preference) = (until, preference);
            return;
        }
        // Full of live routers: the least preferred goes, the newest of
        // those, unless the newcomer ranks no better.
        let i = Self::slot(&self.routers, |r| now >= r.until, |r| (r.preference, u64::MAX - r.learned));
        if self.routers[i].is_some_and(|r| now < r.until && r.preference >= preference) {
            return;
        }
        self.learned += 1;
        self.routers[i] = Some(Router {
            addr: router,
            until,
            preference,
            silent_until: 0,
            learned: self.learned,
        });
    }

    /// A prefix an advertisement says is on the link, for `lifetime`
    /// (0: no longer).
    pub fn on_link(&mut self, prefix: u128, len: u8, lifetime: u64, now: u64) {
        let prefix = prefix & mask(len);
        let known = self.on_link.iter().position(|p| p.is_some_and(|p| p.prefix == prefix && p.len == len));
        if lifetime == 0 {
            if let Some(i) = known {
                self.on_link[i] = None;
            }
            return;
        }
        let i = known.unwrap_or_else(|| {
            Self::slot(&self.on_link, |p| now >= p.until, |p| (Preference::Medium, p.until))
        });
        self.on_link[i] = Some(Prefix {
            prefix,
            len,
            until: now.saturating_add(lifetime),
        });
    }

    /// A route information option (RFC 4191) in `router`'s advertisement:
    /// `prefix` is reached through it, for `lifetime` (0: no longer).
    pub fn route(
        &mut self,
        prefix: u128,
        len: u8,
        router: u128,
        lifetime: u64,
        preference: Preference,
        now: u64,
    ) {
        let prefix = prefix & mask(len);
        let known = self.routes.iter().position(|r| {
            r.is_some_and(|r| r.to.prefix == prefix && r.to.len == len && r.router == router)
        });
        if lifetime == 0 {
            if let Some(i) = known {
                self.routes[i] = None;
            }
            return;
        }
        let i = known.unwrap_or_else(|| {
            Self::slot(&self.routes, |r| now >= r.to.until, |r| (r.preference, r.to.until))
        });
        self.routes[i] = Some(Route {
            to: Prefix {
                prefix,
                len,
                until: now.saturating_add(lifetime),
            },
            router,
            preference,
        });
    }

    /// `router` did not answer neighbour discovery: pass it over until
    /// `until` (if another can be used).
    pub fn silent(&mut self, router: u128, until: u64) {
        if let Some(r) = self.routers.iter_mut().flatten().find(|r| r.addr == router) {
            r.silent_until = until;
        }
    }

    /// `router` was heard from: use it again.
    pub fn heard(&mut self, router: u128) {
        self.silent(router, 0);
    }

    fn is_silent(&self, router: u128, now: u64) -> bool {
        self.routers
            .iter()
            .flatten()
            .any(|r| r.addr == router && now < r.silent_until)
    }

    /// Whether `dst` is on the link by an advertised prefix.
    pub fn is_on_link(&self, dst: u128, now: u64) -> bool {
        self.on_link.iter().flatten().any(|p| p.covers(dst, now))
    }

    /// The default router in use: of those alive, one that answers
    /// before one that does not, then the most preferred, then the one
    /// learned first.
    pub fn default_router(&self, now: u64) -> Option<u128> {
        self.routers
            .iter()
            .flatten()
            .filter(|r| now < r.until)
            .max_by_key(|r| (now >= r.silent_until, r.preference, u64::MAX - r.learned))
            .map(|r| r.addr)
    }

    /// Where a packet for `dst` goes: `dst` itself if it is on the link,
    /// else the router of the longest matching route (one that answers
    /// before one that does not, then the most preferred), else the
    /// default router.
    pub fn next_hop(&self, dst: u128, now: u64) -> Option<u128> {
        if self.is_on_link(dst, now) {
            return Some(dst);
        }
        self.routes
            .iter()
            .flatten()
            .filter(|r| r.to.covers(dst, now))
            .max_by_key(|r| (r.to.len, !self.is_silent(r.router, now), r.preference))
            .map(|r| r.router)
            .or_else(|| self.default_router(now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: u128 = 0xfe80 << 112 | 1;
    const B: u128 = 0xfe80 << 112 | 2;
    const C: u128 = 0xfe80 << 112 | 3;
    const FAR: u128 = 0x2001_0db8_0001 << 80 | 9;
    const NET: u128 = 0xfd00_0003 << 96;
    use Preference::*;

    #[test]
    fn preference_bits() {
        assert_eq!(Preference::from_bits(0b01), High);
        assert_eq!(Preference::from_bits(0b00), Medium);
        assert_eq!(Preference::from_bits(0b11), Low);
        assert_eq!(Preference::from_bits(0b10), Medium);
        assert!(High > Medium && Medium > Low);
    }

    #[test]
    fn no_router_no_route() {
        let r = Routes::new();
        assert_eq!(r.next_hop(FAR, 0), None);
        assert_eq!(r.default_router(0), None);
    }

    #[test]
    fn first_of_equals_stays_in_use() {
        let mut r = Routes::new();
        r.advert(A, 100, Medium, 0);
        r.advert(B, 100, Medium, 1);
        assert_eq!(r.next_hop(FAR, 2), Some(A));
        // Hearing from B again does not move traffic to it.
        r.advert(B, 100, Medium, 3);
        assert_eq!(r.next_hop(FAR, 4), Some(A));
    }

    #[test]
    fn the_preferred_router_wins() {
        let mut r = Routes::new();
        r.advert(A, 100, Medium, 0);
        r.advert(B, 100, High, 0);
        r.advert(C, 100, Low, 0);
        assert_eq!(r.next_hop(FAR, 1), Some(B));
        // A router may change its mind.
        r.advert(B, 100, Low, 2);
        assert_eq!(r.next_hop(FAR, 3), Some(A));
    }

    #[test]
    fn routers_expire_and_resign() {
        let mut r = Routes::new();
        r.advert(A, 10, High, 0);
        r.advert(B, 100, Medium, 0);
        assert_eq!(r.next_hop(FAR, 9), Some(A));
        assert_eq!(r.next_hop(FAR, 10), Some(B));
        // A lifetime of 0: no longer a default router.
        r.advert(B, 0, Medium, 11);
        assert_eq!(r.next_hop(FAR, 12), None);
    }

    #[test]
    fn a_silent_router_is_passed_over_while_another_answers() {
        let mut r = Routes::new();
        r.advert(A, 100, High, 0);
        r.advert(B, 100, Low, 0);
        r.silent(A, 30);
        assert_eq!(r.next_hop(FAR, 1), Some(B));
        // Tried again after a while, or as soon as it is heard from.
        assert_eq!(r.next_hop(FAR, 30), Some(A));
        r.silent(A, 60);
        r.heard(A);
        assert_eq!(r.next_hop(FAR, 31), Some(A));
        // With no other, a silent router is still the only way out.
        r.advert(B, 0, Low, 32);
        r.silent(A, 90);
        assert_eq!(r.next_hop(FAR, 33), Some(A));
    }

    #[test]
    fn on_link_prefixes_go_direct() {
        let mut r = Routes::new();
        r.advert(A, 100, Medium, 0);
        r.on_link(NET | 0xdead, 64, 50, 0);
        assert_eq!(r.next_hop(NET | 7, 1), Some(NET | 7));
        assert_eq!(r.next_hop(FAR, 1), Some(A));
        // Once it runs out, or is withdrawn, the router gets it.
        assert_eq!(r.next_hop(NET | 7, 50), Some(A));
        r.on_link(NET, 64, 50, 60);
        r.on_link(NET, 64, 0, 61);
        assert_eq!(r.next_hop(NET | 7, 62), Some(A));
    }

    #[test]
    fn the_longest_matching_route_wins() {
        let mut r = Routes::new();
        r.advert(A, 100, High, 0);
        r.advert(B, 100, Low, 0);
        r.advert(C, 100, Low, 0);
        // 2001:db8::/32 through B, 2001:db8:1::/48 through C.
        r.route(0x2001_0db8 << 96, 32, B, 100, Medium, 0);
        r.route(0x2001_0db8_0001 << 80, 48, C, 100, Low, 0);
        assert_eq!(r.next_hop(FAR, 1), Some(C));
        assert_eq!(r.next_hop(0x2001_0db8_0002 << 80 | 1, 1), Some(B));
        assert_eq!(r.next_hop(0x2001_0db9 << 96 | 1, 1), Some(A));
        // A route runs out, or is withdrawn.
        r.route(0x2001_0db8_0001 << 80, 48, C, 0, Low, 2);
        assert_eq!(r.next_hop(FAR, 3), Some(B));
        assert_eq!(r.next_hop(FAR, 100), None);
    }

    #[test]
    fn two_routes_to_one_prefix() {
        let mut r = Routes::new();
        r.advert(A, 100, Medium, 0);
        r.advert(B, 100, Medium, 0);
        r.route(0x2001_0db8 << 96, 32, A, 100, Low, 0);
        r.route(0x2001_0db8 << 96, 32, B, 100, High, 0);
        assert_eq!(r.next_hop(FAR, 1), Some(B));
        // The preferred one falls silent: the other carries it.
        r.silent(B, 50);
        assert_eq!(r.next_hop(FAR, 2), Some(A));
        assert_eq!(r.next_hop(FAR, 50), Some(B));
    }

    #[test]
    fn a_full_table_keeps_the_better_routers() {
        let mut r = Routes::new();
        for i in 0..ENTRIES as u128 {
            r.advert(A + 16 + i, 100, Medium, i as u64);
        }
        // No room for one that is no better.
        r.advert(B, 100, Medium, 10);
        assert_eq!(r.default_router(11), Some(A + 16));
        r.advert(C, 100, Low, 10);
        assert_ne!(r.default_router(11), Some(C));
        // A better one takes the place of the newest of the rest.
        r.advert(B, 100, High, 12);
        assert_eq!(r.default_router(13), Some(B));
        r.advert(B, 0, High, 14);
        assert_eq!(r.default_router(15), Some(A + 16));
        // An expired one's place is free.
        r.advert(C, 100, Low, 200);
        assert_eq!(r.default_router(201), Some(C));
    }
}
