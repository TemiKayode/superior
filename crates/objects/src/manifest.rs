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
//!   start lazy              # boot (default): at boot; lazy: on first call;
//!                           # clone: only as a copy-on-write clone of a
//!                           # running component with the same image;
//!                           # launch: when a launcher asks
//!   priority 10             # default 10
//!   budget 2 10             # 2 ticks of CPU time in every 10, shared by
//!                           # all its threads (default: unlimited)
//!   arg 0                   # passed in its first argument register
//!   memory 20               # bits of untyped memory for this instance
//!   restart one-for-one     # or rest-for-one, or never
//!   provides echo 0         # receive side of service "echo" in slot 0
//! component client
//!   image client
//!   uses echo 0             # a badged client capability to "echo"
//!   manages window 4        # the same, its badge marked a manager's
//!                           # (`MANAGER_BADGE`): the server lets it do
//!                           # more (the desktop shell, say)
//!   control 1               # an endpoint to the Component Manager
//!   device uart 2           # a device capability the CM was given
//!   notification 3          # a fresh notification
//!   untyped 16 4            # a fresh 2^16-byte untyped block
//!   untyped spare 8         # the rest of RAM: every block the kernel
//!                           # handed the manager as spare, slots 8 on
//!   state 5                 # a page the manager keeps across restarts
//!   shared 9 16             # 9 pages (slots 16-24) kept across restarts,
//!                           # to share with a server (rings, buffers)
//!   cspace 9                # a CSpace of 2^9 slots (default 2^6)
//!   vspace 18               # an address space of 2^18 bytes, page
//!                           # tables included (default 2^16)
//!   quota 64                # pages the Memory Server may give it
//!   heap 32                 # a demand-zero heap of 32 pages
//!   fault-injector          # may ask the manager to kill components
//!   power                   # hears SUSPEND and RESUME (`power`) on its
//!                           # first service when the machine suspends
//!   power-control           # may ask the manager to suspend the machine
//!   update-control          # may confirm the system came up and stage
//!                           # an update (`crate::ab`)
//!   install-control         # may install and uninstall app packages
//!                           # (`crate::package`)
//!   launch-control          # may start `start launch` components
//!                           # (`crate::interfaces::launch`)
//! ```
//!
//! Before any component, `system block` says the rest of the system is in
//! A/B slots on the disk behind service `block` (`crate::ab`): the manager
//! starts the components here, then loads the system bundle from a slot
//! and starts its components as if their manifest followed this one.
//! `packages block` keeps a store of signed app packages on that disk
//! (`crate::package`), installed at boot; each `app-service <name>` names
//! a service apps may use (nothing else is offered to them).
//!
//! Slots are in the component's own CSpace, a CNode of [`CSPACE_SLOTS`]
//! (more after a `cspace` directive, up to 2^16 nameable here).
//! Parsing checks everything that can be checked without the bundle:
//! unique names, slots in range and not reused, every `uses` matching
//! some `provides`, and every lazy component providing something (or it
//! could never start).

pub const MAX_COMPONENTS: usize = 16;
/// The longest budget period, in ticks.
pub const MAX_PERIOD: u64 = 100_000;
/// Capabilities a component is given (the Linux personality, with its
/// thirty-five files, has 42).
pub const MAX_CAPS: usize = 48;
/// Every component's CSpace size, in bits and slots.
pub const CSPACE_BITS: u8 = 6;
pub const CSPACE_SLOTS: usize = 1 << CSPACE_BITS;
/// Bounds on a component's CSpace, in bits.
pub const CSPACE_MAX_BITS: u8 = 18;
/// Most pages a heap may span.
pub const MAX_HEAP_PAGES: u64 = 4096;
/// Bounds on the per-instance untyped block, in bits (at most the
/// manager's least memory, [`root::UNTYPED_BITS`](crate::abi::root::UNTYPED_BITS)).
pub const MEMORY_MIN_BITS: u8 = 16;
pub const MEMORY_MAX_BITS: u8 = 26;
pub const DEFAULT_MEMORY_BITS: u8 = 20;
/// Bounds on a component's address space (its top table and the pool its
/// page tables come from), in bits: 2^16 bytes holds 15 page tables, for
/// some 30 MiB mapped; a driver mapping a video card's memory needs more.
pub const VSPACE_BITS: u8 = 16;
pub const VSPACE_MAX_BITS: u8 = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
    Boot,
    Lazy,
    /// Started only when a running component with the same image asks the
    /// manager to clone itself into it (copy-on-write heap).
    Clone,
    /// Started only when a component with `launch-control` asks, and again
    /// after it has exited.
    Launch,
}

/// The bit a `manages` capability's badge has, beside the client's
/// number: a server gives such a client more (the compositor lets the
/// desktop shell see and raise every client's windows). No client can set
/// it on a badge of its own.
pub const MANAGER_BADGE: u64 = 1 << 32;

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
    /// As `Uses`, its badge marked with [`MANAGER_BADGE`].
    Manages(&'a str),
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
    /// The rest of RAM: the untyped blocks the kernel gave the manager as
    /// spare (`root::SPARE`), each made over whole into the component's
    /// slots from this one on, as many as there are. For the Memory
    /// Server.
    Spare,
    /// A file of the bundle, copied into pages of the component's own
    /// memory, in consecutive slots from this one (the last page padded
    /// with zeros): data a component reads, like the Linux personality's
    /// programs.
    File(&'a str),
}

/// Most `app-service` lines.
pub const MAX_APP_SERVICES: usize = 8;

/// Most pages one `shared` directive may ask for.
pub const MAX_SHARED_PAGES: u8 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapSpec<'a> {
    pub kind: CapKind<'a>,
    pub slot: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Component<'a> {
    pub name: &'a str,
    pub image: &'a str,
    pub start: Start,
    pub restart: Restart,
    pub priority: u8,
    /// CPU time: `(budget, period)` in ticks, one scheduling context all
    /// its threads share; `None` runs it unlimited.
    pub budget: Option<(u32, u32)>,
    pub arg: u64,
    pub memory_bits: u8,
    /// Its CSpace size in bits.
    pub cspace_bits: u8,
    /// Its address space's size in bits.
    pub vspace_bits: u8,
    /// Pages the Memory Server may give it (heap and frames together).
    pub quota_pages: u64,
    /// Pages of demand-zero heap at `USER_BASE + mem::HEAP_OFFSET`.
    pub heap_pages: u64,
    /// May ask the manager (through its `control` capability) to kill
    /// other components: for fault-injection tests.
    pub injector: bool,
    /// Takes part in suspend and resume: the manager calls its first
    /// service, unbadged, with `power::SUSPEND` and `power::RESUME`.
    pub power: bool,
    /// May ask the manager to suspend the machine.
    pub power_control: bool,
    /// May confirm the system came up, and stage an update.
    pub update_control: bool,
    /// May install and uninstall app packages.
    pub install_control: bool,
    /// May start `start launch` components.
    pub launch_control: bool,
    /// The icon a launcher shows for it (one of the toolkit's names, or an
    /// image file in its bundle, `superior_objects::image`), if any.
    pub icon: &'a str,
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
            budget: None,
            arg: 0,
            memory_bits: DEFAULT_MEMORY_BITS,
            cspace_bits: CSPACE_BITS,
            vspace_bits: VSPACE_BITS,
            quota_pages: 0,
            heap_pages: 0,
            injector: false,
            power: false,
            power_control: false,
            update_control: false,
            install_control: false,
            launch_control: false,
            icon: "",
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
    /// The service whose disk holds the system slots (`system`), if any.
    pub system: Option<&'a str>,
    /// The service whose disk holds the package store (`packages`).
    pub packages: Option<&'a str>,
    /// Services apps may use (`app-service`).
    pub app_services: [Option<&'a str>; MAX_APP_SERVICES],
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

    /// Whether apps may use `service`.
    pub fn offers(&self, service: &str) -> bool {
        self.app_services.iter().flatten().any(|s| *s == service)
    }

    /// Whether any top-level directive (`system`, `packages`,
    /// `app-service`) is set.
    pub fn configures_system(&self) -> bool {
        self.system.is_some() || self.packages.is_some() || self.app_services[0].is_some()
    }

    pub fn parse(text: &'a str) -> Result<Manifest<'a>, ParseError<'a>> {
        let m = Self::parse_unchecked(text)?;
        m.check()?;
        Ok(m)
    }

    /// Parses without the checks across components: a package's
    /// manifest, whose `uses` name services of the system it joins
    /// (`crate::package::admit` checks those).
    pub fn parse_unchecked(text: &'a str) -> Result<Manifest<'a>, ParseError<'a>> {
        let mut m = Manifest {
            components: [None; MAX_COMPONENTS],
            system: None,
            packages: None,
            app_services: [None; MAX_APP_SERVICES],
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
            if key == "system" {
                if cur.is_some() || m.system.is_some() {
                    return Err(err("system comes once, before any component", key));
                }
                m.system = Some(arg("system needs a service")?);
                continue;
            }
            if key == "packages" {
                if cur.is_some() || m.packages.is_some() {
                    return Err(err("packages comes once, before any component", key));
                }
                m.packages = Some(arg("packages needs a service")?);
                continue;
            }
            if key == "app-service" {
                let s = arg("app-service needs a service")?;
                if cur.is_some() {
                    return Err(err("app-service comes before any component", key));
                }
                let free = m
                    .app_services
                    .iter_mut()
                    .find(|x| x.is_none())
                    .ok_or(err("too many app services", s))?;
                *free = Some(s);
                continue;
            }
            let c = match cur {
                Some(i) => m.components[i].as_mut().unwrap(),
                None => return Err(err("directive before any component", key)),
            };
            let number = |w: &'a str| -> Result<u64, ParseError<'a>> {
                w.parse::<u64>().map_err(|_| err("expected a number", w))
            };
            // Slots past the usual CSpace are for a component whose
            // `cspace` directive, earlier, made it larger.
            let slots = (1usize << c.cspace_bits).min(1 << 16);
            let slot = |w: &'a str| -> Result<u16, ParseError<'a>> {
                match w.parse::<usize>() {
                    Ok(s) if s < slots => Ok(s as u16),
                    _ => Err(err("slot out of range", w)),
                }
            };
            let cap = match key {
                "image" => {
                    c.image = arg("image needs a bundle entry")?;
                    None
                }
                "start" => {
                    let w = arg("start needs boot, lazy, clone or launch")?;
                    c.start = match w {
                        "boot" => Start::Boot,
                        "lazy" => Start::Lazy,
                        "clone" => Start::Clone,
                        "launch" => Start::Launch,
                        _ => return Err(err("start must be boot, lazy, clone or launch", w)),
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
                "budget" => {
                    let b = arg("budget needs ticks and a period")?;
                    let w = arg("budget needs ticks and a period")?;
                    match (number(b)?, number(w)?) {
                        (b @ 1.., p @ 1..=MAX_PERIOD) if b <= p => {
                            c.budget = Some((b as u32, p as u32))
                        }
                        _ => return Err(err("budget must be 1 to its period, at most 100000", w)),
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
                        _ => return Err(err("memory must be 16 to 26 bits", w)),
                    }
                    None
                }
                "cspace" => {
                    let w = arg("cspace needs a size in bits")?;
                    match number(w)? {
                        b if (CSPACE_BITS as u64..=CSPACE_MAX_BITS as u64).contains(&b) => {
                            c.cspace_bits = b as u8
                        }
                        _ => return Err(err("cspace must be 6 to 18 bits", w)),
                    }
                    None
                }
                "vspace" => {
                    let w = arg("vspace needs a size in bits")?;
                    match number(w)? {
                        b if (VSPACE_BITS as u64..=VSPACE_MAX_BITS as u64).contains(&b) => {
                            c.vspace_bits = b as u8
                        }
                        _ => return Err(err("vspace must be 16 to 20 bits", w)),
                    }
                    None
                }
                "fault-injector" => {
                    c.injector = true;
                    None
                }
                "power" => {
                    c.power = true;
                    None
                }
                "power-control" => {
                    c.power_control = true;
                    None
                }
                "update-control" => {
                    c.update_control = true;
                    None
                }
                "install-control" => {
                    c.install_control = true;
                    None
                }
                "launch-control" => {
                    c.launch_control = true;
                    None
                }
                "icon" => {
                    c.icon = arg("icon needs a name")?;
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
                "manages" => {
                    let s = arg("manages needs a service name")?;
                    Some((CapKind::Manages(s), arg("manages needs a slot")?))
                }
                "device" => {
                    let d = arg("device needs a name")?;
                    Some((CapKind::Device(d), arg("device needs a slot")?))
                }
                "notification" => Some((CapKind::Notification, arg("notification needs a slot")?)),
                "control" => Some((CapKind::Control, arg("control needs a slot")?)),
                "file" => {
                    let f = arg("file needs a bundle entry")?;
                    Some((CapKind::File(f), arg("file needs a slot")?))
                }
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
                    if w == "spare" {
                        if c.caps().any(|x| x.kind == CapKind::Spare) {
                            return Err(err("untyped spare given twice", w));
                        }
                        Some((CapKind::Spare, arg("untyped spare needs a slot")?))
                    } else {
                    let bits = match number(w)? {
                        b @ 12..=MEMORY_MAX_BITS_U64 => b as u8,
                        _ => return Err(err("untyped must be 12 to 24 bits", w)),
                    };
                    Some((CapKind::Untyped(bits), arg("untyped needs a slot")?))
                    }
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
            if c.power && c.provides().next().is_none() {
                return Err(err("a power component must provide a service", c.name));
            }
            // Its heap arrives from the component it is cloned from.
            if c.start == Start::Clone && c.heap_pages == 0 {
                return Err(err("a clone needs a heap", c.name));
            }
            // A heap is paged in by the Memory Server.
            if c.heap_pages > 0 && self.provider("mem").is_none() {
                return Err(err("a heap needs a component providing mem", c.name));
            }
            for cap in c.caps() {
                match cap.kind {
                    CapKind::Uses(s) | CapKind::Manages(s) if self.provider(s).is_none() => {
                        return Err(err("no component provides this service", s));
                    }
                    CapKind::Provides(s) if self.provider(s) != Some(i) => {
                        return Err(err("service provided twice", s));
                    }
                    _ => {}
                }
            }
        }
        if let Some(s) = self.system {
            if self.provider(s).is_none() {
                return Err(err("no component provides the system disk's service", s));
            }
        }
        if let Some(s) = self.packages {
            if self.provider(s).is_none() {
                return Err(err("no component provides the package store's service", s));
            }
        }
        for s in self.app_services.iter().flatten() {
            if self.provider(s).is_none() {
                return Err(err("no component provides this app service", s));
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
  vspace 18
  quota 10
  heap 4
  fault-injector
  power-control
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
        assert!(client.power_control && !client.power && !echo.power_control);
        assert_eq!(echo.cspace_bits, CSPACE_BITS);
        assert_eq!((client.vspace_bits, echo.vspace_bits), (18, VSPACE_BITS));
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
    fn a_budget_is_ticks_in_a_period() {
        let m = Manifest::parse("component a
 image a
 budget 2 10
component b
 image b").unwrap();
        assert_eq!(m.components[0].as_ref().unwrap().budget, Some((2, 10)));
        assert_eq!(m.components[1].as_ref().unwrap().budget, None, "unlimited by default");
    }

    #[test]
    fn untyped_spare_names_its_first_slot_once() {
        let m = Manifest::parse(
            "component mem
 image memserver
 cspace 17
 provides mem 0
 untyped spare 8",
        )
        .unwrap();
        let c = m.components[0].as_ref().unwrap();
        assert_eq!(c.cspace_bits, 17);
        assert!(c.caps().any(|x| x.kind == CapKind::Spare && x.slot == 8));
        assert_eq!(
            error("component a
 image a
 untyped spare 8
 untyped spare 9"),
            (4, "untyped spare given twice")
        );
        assert_eq!(
            error("component a
 image a
 untyped spare"),
            (3, "untyped spare needs a slot")
        );
    }

    #[test]
    fn the_desktop_shell_launches_and_manages() {
        let m = Manifest::parse(
            "component compositor\n image compositor\n provides window 1\n\
             component panel\n image panel\n manages window 0\n control 1\n launch-control\n\
             component app\n image app\n start launch\n icon wave\n uses window 0\n",
        )
        .unwrap();
        let (_, panel) = m.iter().nth(1).unwrap();
        assert!(panel.launch_control);
        assert_eq!((panel.icon, m.iter().nth(2).unwrap().1.icon), ("", "wave"));
        assert_eq!(panel.caps().next().unwrap().kind, CapKind::Manages("window"));
        assert_eq!(m.iter().nth(2).unwrap().1.start, Start::Launch);
        assert_eq!(
            Manifest::parse("component a\n image a\n manages nothing 0\n").unwrap_err().what,
            "no component provides this service"
        );
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
            (3, "start must be boot, lazy, clone or launch")
        );
        assert_eq!(
            error("component a
 image a
 start clone"),
            (0, "a clone needs a heap")
        );
        assert_eq!(
            error("component a\n image a\n priority 63"),
            (3, "priority must be 1 to 62")
        );
        assert_eq!(
            error("component a\n image a\n budget 3 2"),
            (3, "budget must be 1 to its period, at most 100000")
        );
        assert_eq!(
            error("component a\n image a\n budget 0 2"),
            (3, "budget must be 1 to its period, at most 100000")
        );
        assert_eq!(
            error("component a\n image a\n budget 2"),
            (3, "budget needs ticks and a period")
        );
        assert_eq!(
            error("component a\n image a\n memory 30"),
            (3, "memory must be 16 to 26 bits")
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
            error("component a\n image a\n cspace 19"),
            (3, "cspace must be 6 to 18 bits")
        );
        assert_eq!(
            error("component a
 image a
 vspace 21"),
            (3, "vspace must be 16 to 20 bits")
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
        let m = Manifest::parse("system block\ncomponent d\n image d\n provides block 1").unwrap();
        assert_eq!(m.system, Some("block"));
        assert_eq!(Manifest::parse(EXAMPLE).unwrap().system, None);
        assert_eq!(
            error("component d\n image d\n provides block 1\nsystem block"),
            (4, "system comes once, before any component")
        );
        assert_eq!(
            error("system block\ncomponent d\n image d"),
            (0, "no component provides the system disk's service")
        );
        assert_eq!(
            error("component a\n image a\n power"),
            (0, "a power component must provide a service")
        );
        assert_eq!(
            error("component a\n image a\n provides s 0\ncomponent b\n image b\n provides s 0"),
            (0, "service provided twice")
        );
    }
}
