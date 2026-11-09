//! Component manifests: what the Component Manager starts, when, and with
//! which capabilities (spec section 4: "the parent builds each child's
//! namespace from the capabilities in the child's manifest").
//!
//! A manifest is plain text, one directive per line; `#` starts a comment.
//! `component` opens a component and the lines after it describe it:
//!
//! ```text
//! component echo
//!   image echo              # bundle entry holding its executable
//!   start lazy              # boot (default): at boot; lazy: on first call
//!   priority 10             # default 10
//!   arg 0                   # passed in its first argument register
//!   memory 20               # bits of untyped memory for this instance
//!   restart one-for-one     # or rest-for-one, or never
//!   provides echo 0         # receive side of service "echo" in slot 0
//! component client
//!   image client
//!   uses echo 0             # a badged client capability to "echo"
//!   control 1               # an endpoint to the Component Manager
//!   device uart 2           # a device capability the CM was given
//!   notification 3          # a fresh notification
//!   untyped 16 4            # a fresh 2^16-byte untyped block
//!   state 5                 # a page the manager keeps across restarts
//!   shared 9 16             # 9 pages (slots 16-24) kept across restarts,
//!                           # to share with a server (rings, buffers)
//!   cspace 9                # a CSpace of 2^9 slots (default 2^6)
//!   quota 64                # pages the Memory Server may give it
//!   heap 32                 # a demand-zero heap of 32 pages
//!   fault-injector          # may ask the manager to kill components
//! ```
//!
//! Slots are in the component's own CSpace, a CNode of [`CSPACE_SLOTS`].
//! Parsing checks everything that can be checked without the bundle:
//! unique names, slots in range and not reused, every `uses` matching
//! some `provides`, and every lazy component providing something (or it
//! could never start).

pub const MAX_COMPONENTS: usize = 16;
pub const MAX_CAPS: usize = 12;
/// Every component's CSpace size, in bits and slots.
pub const CSPACE_BITS: u8 = 6;
pub const CSPACE_SLOTS: usize = 1 << CSPACE_BITS;
/// Bounds on a component's CSpace, in bits.
pub const CSPACE_MAX_BITS: u8 = 10;
/// Most pages a heap may span.
pub const MAX_HEAP_PAGES: u64 = 4096;
/// Bounds on the per-instance untyped block, in bits.
pub const MEMORY_MIN_BITS: u8 = 16;
pub const MEMORY_MAX_BITS: u8 = 24;
pub const DEFAULT_MEMORY_BITS: u8 = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
    Boot,
    Lazy,
}

/// What happens when the component dies (spec section 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Restart {
    /// Restart just it.
    OneForOne,
    /// Restart it and every component started after it.
    RestForOne,
    /// Leave it stopped.
    Never,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapKind<'a> {
    Provides(&'a str),
    Uses(&'a str),
    Device(&'a str),
    Notification,
    Untyped(u8),
    Control,
    /// A 4 KiB page that outlives instances: the manager makes it once and
    /// gives every instance of the component a copy, so a restarted
    /// instance finds what the last one wrote (spec section 4: "state is
    /// external"). At most one per component.
    State,
    /// `n` pages in consecutive slots, made once like [`CapKind::State`]:
    /// memory a component shares with a server (rings and buffers). The
    /// manager holds the originals, so when either side is restarted only
    /// its own copies go, and the other side's mappings stay.
    Shared(u8),
}

/// Most pages one `shared` directive may ask for.
pub const MAX_SHARED_PAGES: u8 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapSpec<'a> {
    pub kind: CapKind<'a>,
    pub slot: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Component<'a> {
    pub name: &'a str,
    pub image: &'a str,
    pub start: Start,
    pub restart: Restart,
    pub priority: u8,
    pub arg: u64,
    pub memory_bits: u8,
    /// Its CSpace size in bits.
    pub cspace_bits: u8,
    /// Pages the Memory Server may give it (heap and frames together).
    pub quota_pages: u64,
    /// Pages of demand-zero heap at `USER_BASE + mem::HEAP_OFFSET`.
    pub heap_pages: u64,
    /// May ask the manager (through its `control` capability) to kill
    /// other components: for fault-injection tests.
    pub injector: bool,
    pub caps: [Option<CapSpec<'a>>; MAX_CAPS],
}

impl<'a> Component<'a> {
    fn new(name: &'a str) -> Self {
        Component {
            name,
            image: "",
            start: Start::Boot,
            restart: Restart::OneForOne,
            priority: 10,
            arg: 0,
            memory_bits: DEFAULT_MEMORY_BITS,
            cspace_bits: CSPACE_BITS,
            quota_pages: 0,
            heap_pages: 0,
            injector: false,
            caps: [None; MAX_CAPS],
        }
    }

    pub fn caps(&self) -> impl Iterator<Item = CapSpec<'a>> + '_ {
        self.caps.iter().flatten().copied()
    }

    /// The services this component provides.
    pub fn provides(&self) -> impl Iterator<Item = &'a str> + '_ {
        self.caps().filter_map(|c| match c.kind {
            CapKind::Provides(s) => Some(s),
            _ => None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseError<'a> {
    /// 1-based line number; 0 for whole-manifest checks.
    pub line: usize,
    pub what: &'static str,
    /// The offending word, if any.
    pub word: &'a str,
}

#[derive(Clone, Copy, Debug)]
pub struct Manifest<'a> {
    pub components: [Option<Component<'a>>; MAX_COMPONENTS],
}

impl<'a> Manifest<'a> {
    pub fn iter(&self) -> impl Iterator<Item = (usize, &Component<'a>)> + '_ {
        self.components
            .iter()
            .enumerate()
            .filter_map(|(i, c)| c.as_ref().map(|c| (i, c)))
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The component providing `service`.
    pub fn provider(&self, service: &str) -> Option<usize> {
        self.iter()
            .find(|(_, c)| c.provides().any(|s| s == service))
            .map(|(i, _)| i)
    }

    pub fn parse(text: &'a str) -> Result<Manifest<'a>, ParseError<'a>> {
        let mut m = Manifest {
            components: [None; MAX_COMPONENTS],
        };
        let mut cur: Option<usize> = None;
        let mut count = 0;
        for (n, raw) in text.lines().enumerate() {
            let line = n + 1;
            let err = |what, word| ParseError { line, what, word };
            let code = raw.split('#').next().unwrap_or("");
            let mut words = code.split_whitespace();
            let Some(key) = words.next() else {
                continue;
            };
            let mut arg = |what: &'static str| words.next().ok_or(err(what, key));
            if key == "component" {
                let name = arg("component needs a name")?;
                if m.iter().any(|(_, c)| c.name == name) {
                    return Err(err("duplicate component name", name));
                }
                if count == MAX_COMPONENTS {
                    return Err(err("too many components", name));
                }
                m.components[count] = Some(Component::new(name));
                cur = Some(count);
                count += 1;
                continue;
            }
            let c = match cur {
                Some(i) => m.components[i].as_mut().unwrap(),
                None => return Err(err("directive before any component", key)),
            };
            let number = |w: &'a str| -> Result<u64, ParseError<'a>> {
                w.parse::<u64>().map_err(|_| err("expected a number", w))
            };
            let slot = |w: &'a str| -> Result<u8, ParseError<'a>> {
                match w.parse::<usize>() {
                    Ok(s) if s < CSPACE_SLOTS => Ok(s as u8),
                    _ => Err(err("slot out of range", w)),
                }
            };
            let cap = match key {
                "image" => {
                    c.image = arg("image needs a bundle entry")?;
                    None
                }
                "start" => {
                    let w = arg("start needs boot or lazy")?;
                    c.start = match w {
                        "boot" => Start::Boot,
                        "lazy" => Start::Lazy,
                        _ => return Err(err("start must be boot or lazy", w)),
                    };
                    None
                }
                "restart" => {
                    let w = arg("restart needs a strategy")?;
                    c.restart = match w {
                        "one-for-one" => Restart::OneForOne,
                        "rest-for-one" => Restart::RestForOne,
                        "never" => Restart::Never,
                        _ => return Err(err("unknown restart strategy", w)),
                    };
                    None
                }
                "priority" => {
                    let w = arg("priority needs a number")?;
                    match number(w)? {
                        p @ 1..=62 => c.priority = p as u8,
                        _ => return Err(err("priority must be 1 to 62", w)),
                    }
                    None
                }
                "arg" => {
                    c.arg = number(arg("arg needs a number")?)?;
                    None
                }
                "memory" => {
                    let w = arg("memory needs a size in bits")?;
                    match number(w)? {
                        b if (MEMORY_MIN_BITS as u64..=MEMORY_MAX_BITS as u64).contains(&b) => {
                            c.memory_bits = b as u8
                        }
                        _ => return Err(err("memory must be 16 to 24 bits", w)),
                    }
                    None
                }
                "cspace" => {
                    let w = arg("cspace needs a size in bits")?;
                    match number(w)? {
                        b if (CSPACE_BITS as u64..=CSPACE_MAX_BITS as u64).contains(&b) => {
                            c.cspace_bits = b as u8
                        }
                        _ => return Err(err("cspace must be 6 to 10 bits", w)),
                    }
                    None
                }
                "fault-injector" => {
                    c.injector = true;
                    None
                }
                "quota" => {
                    c.quota_pages = number(arg("quota needs a page count")?)?;
                    None
                }
                "heap" => {
                    let w = arg("heap needs a page count")?;
                    match number(w)? {
                        p @ 1..=MAX_HEAP_PAGES => c.heap_pages = p,
                        _ => return Err(err("heap must be 1 to 4096 pages", w)),
                    }
                    None
                }
                "provides" => {
                    let s = arg("provides needs a service name")?;
                    Some((CapKind::Provides(s), arg("provides needs a slot")?))
                }
                "uses" => {
                    let s = arg("uses needs a service name")?;
                    Some((CapKind::Uses(s), arg("uses needs a slot")?))
                }
                "device" => {
                    let d = arg("device needs a name")?;
                    Some((CapKind::Device(d), arg("device needs a slot")?))
                }
                "notification" => Some((CapKind::Notification, arg("notification needs a slot")?)),
                "control" => Some((CapKind::Control, arg("control needs a slot")?)),
                "state" => {
                    if c.caps().any(|x| x.kind == CapKind::State) {
                        return Err(err("only one state page per component", key));
                    }
                    Some((CapKind::State, arg("state needs a slot")?))
                }
                "shared" => {
                    if c.caps().any(|x| matches!(x.kind, CapKind::Shared(_))) {
                        return Err(err("only one shared directive per component", key));
                    }
                    let w = arg("shared needs a page count")?;
                    let n = match number(w)? {
                        n @ 1..=MAX_SHARED_PAGES_U64 => n as u8,
                        _ => return Err(err("shared must be 1 to 16 pages", w)),
                    };
                    Some((CapKind::Shared(n), arg("shared needs a slot")?))
                }
                "untyped" => {
                    let w = arg("untyped needs a size in bits")?;
                    let bits = match number(w)? {
                        b @ 12..=MEMORY_MAX_BITS_U64 => b as u8,
                        _ => return Err(err("untyped must be 12 to 24 bits", w)),
                    };
                    Some((CapKind::Untyped(bits), arg("untyped needs a slot")?))
                }
                _ => return Err(err("unknown directive", key)),
            };
            if let Some((kind, w)) = cap {
                let slot = slot(w)?;
                if c.caps().any(|x| x.slot == slot) {
                    return Err(err("slot used twice", w));
                }
                let free = c
                    .caps
                    .iter_mut()
                    .find(|x| x.is_none())
                    .ok_or(err("too many capabilities", key))?;
                *free = Some(CapSpec { kind, slot });
            }
            if let Some(extra) = words.next() {
                return Err(err("unexpected word", extra));
            }
        }
        m.check()?;
        Ok(m)
    }

    /// Checks across components.
    fn check(&self) -> Result<(), ParseError<'a>> {
        let err = |what, word| ParseError {
            line: 0,
            what,
            word,
        };
        for (i, c) in self.iter() {
            if c.image.is_empty() {
                return Err(err("component has no image", c.name));
            }
            if c.start == Start::Lazy && c.provides().next().is_none() {
                return Err(err("a lazy component must provide a service", c.name));
            }
            // A heap is paged in by the Memory Server.
            if c.heap_pages > 0 && self.provider("mem").is_none() {
                return Err(err("a heap needs a component providing mem", c.name));
            }
            for cap in c.caps() {
                match cap.kind {
                    CapKind::Uses(s) if self.provider(s).is_none() => {
                        return Err(err("no component provides this service", s));
                    }
                    CapKind::Provides(s) if self.provider(s) != Some(i) => {
                        return Err(err("service provided twice", s));
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

const MEMORY_MAX_BITS_U64: u64 = MEMORY_MAX_BITS as u64;
const MAX_SHARED_PAGES_U64: u64 = MAX_SHARED_PAGES as u64;

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = "
# a lazily started service and its client
component echo
  image echo
  start lazy
  provides echo 0
component client   # comment after a directive
  image client
  priority 9
  arg 7
  restart rest-for-one
  uses echo 0
  control 1
  device uart 2
  notification 3
  untyped 16 4
  state 5
  cspace 8
  quota 10
  heap 4
  fault-injector
component memserver
  image memserver
  provides mem 0
";

    #[test]
    fn parses_components_and_caps() {
        let m = Manifest::parse(EXAMPLE).unwrap();
        assert_eq!(m.len(), 3);
        let echo = m.components[0].unwrap();
        assert_eq!(
            (echo.name, echo.image, echo.start),
            ("echo", "echo", Start::Lazy)
        );
        assert_eq!(echo.restart, Restart::OneForOne);
        assert_eq!(echo.memory_bits, DEFAULT_MEMORY_BITS);
        let client = m.components[1].unwrap();
        assert_eq!(
            (client.priority, client.arg, client.start),
            (9, 7, Start::Boot)
        );
        assert_eq!(client.restart, Restart::RestForOne);
        assert_eq!(
            (client.cspace_bits, client.quota_pages, client.heap_pages),
            (8, 10, 4)
        );
        assert!(client.injector && !echo.injector);
        assert_eq!(echo.cspace_bits, CSPACE_BITS);
        let caps: std::vec::Vec<_> = client.caps().collect();
        assert_eq!(
            caps,
            [
                CapSpec {
                    kind: CapKind::Uses("echo"),
                    slot: 0
                },
                CapSpec {
                    kind: CapKind::Control,
                    slot: 1
                },
                CapSpec {
                    kind: CapKind::Device("uart"),
                    slot: 2
                },
                CapSpec {
                    kind: CapKind::Notification,
                    slot: 3
                },
                CapSpec {
                    kind: CapKind::Untyped(16),
                    slot: 4
                },
                CapSpec {
                    kind: CapKind::State,
                    slot: 5
                },
            ]
        );
        assert_eq!(m.provider("echo"), Some(0));
        assert_eq!(m.provider("net"), None);
    }

    fn error(text: &str) -> (usize, &'static str) {
        let e = Manifest::parse(text).unwrap_err();
        (e.line, e.what)
    }

    #[test]
    fn rejects_bad_manifests() {
        assert_eq!(error("image x"), (1, "directive before any component"));
        assert_eq!(
            error("component a\ncomponent a"),
            (2, "duplicate component name")
        );
        assert_eq!(
            error("component a\n image a\n frob 1"),
            (3, "unknown directive")
        );
        assert_eq!(
            error("component a\n image a\n control 64"),
            (3, "slot out of range")
        );
        assert_eq!(
            error("component a\n image a\n control 1\n notification 1"),
            (4, "slot used twice")
        );
        assert_eq!(
            error("component a\n image a\n start soon"),
            (3, "start must be boot or lazy")
        );
        assert_eq!(
            error("component a\n image a\n priority 63"),
            (3, "priority must be 1 to 62")
        );
        assert_eq!(
            error("component a\n image a\n memory 30"),
            (3, "memory must be 16 to 24 bits")
        );
        assert_eq!(
            error("component a\n image a\n control 1 2"),
            (3, "unexpected word")
        );
        assert_eq!(
            error(
                "component a
 image a
 state 1
 state 2"
            ),
            (4, "only one state page per component")
        );
        assert_eq!(
            error(
                "component a
 image a
 shared 17 1"
            ),
            (3, "shared must be 1 to 16 pages")
        );
        assert_eq!(
            error(
                "component a
 image a
 shared 2 1
 shared 1 9"
            ),
            (4, "only one shared directive per component")
        );
        let m = Manifest::parse(
            "component a
 image a
 shared 9 16",
        )
        .unwrap();
        assert!(
            m.components[0]
                .unwrap()
                .caps()
                .any(|c| c.kind == CapKind::Shared(9) && c.slot == 16)
        );
        assert_eq!(
            error("component a\n image a\n cspace 11"),
            (3, "cspace must be 6 to 10 bits")
        );
        assert_eq!(
            error("component a\n image a\n heap 0"),
            (3, "heap must be 1 to 4096 pages")
        );
        assert_eq!(
            error("component a\n image a\n heap 4"),
            (0, "a heap needs a component providing mem")
        );
        assert_eq!(error("component a"), (0, "component has no image"));
        assert_eq!(
            error("component a\n image a\n uses net 0"),
            (0, "no component provides this service")
        );
        assert_eq!(
            error("component a\n image a\n start lazy"),
            (0, "a lazy component must provide a service")
        );
        assert_eq!(
            error("component a\n image a\n provides s 0\ncomponent b\n image b\n provides s 0"),
            (0, "service provided twice")
        );
    }
}
