//! A Wayland display server, in the personality: what a Wayland client
//! (a toolkit, a browser) draws through, shown on Superior's compositor.
//! It listens on the Unix socket [`SOCKET`] (so `XDG_RUNTIME_DIR=/tmp`)
//! and speaks Wayland's wire protocol to each client that connects: the
//! core (`wl_display`, `wl_registry`, `wl_callback`), `wl_compositor`
//! with surfaces and regions, `wl_shm` with pools and buffers (a pool's
//! memory a memory file, [`crate::Shm`], passed with it), and
//! `xdg_wm_base` with `xdg_surface` and `xdg_toplevel`.
//!
//! Each toplevel is a window of the compositor's, undecorated (a Wayland
//! client draws its own), made the size of the first buffer committed to
//! it and remade if that changes. Its pages are shared pages of its own:
//! a window's pages are lent once, so each commit copies the buffer in,
//! and the buffer is released at once. A frame callback is done when its
//! commit is shown. The window's close box closes the toplevel. Input
//! (`wl_seat`) is not served yet.
//!
//! The server's tables are in shared pages kept for them ([`WL_PAGES`]),
//! not in the personality's state, which has no room.

use crate::{
    EINVAL, ENOMEM, FileKind, PAGE, SHM_PAGES, SHM_SLOTS, SHM_VA, State, TICK_HZ, fb_call, unix, unix_new, window,
};

/// Where clients connect: `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`.
pub const SOCKET: &[u8] = b"/tmp/wayland-0";
/// The shared pages, from the first, the server's tables are kept in.
pub const WL_PAGES: u64 = 8;

const MAX_CLIENTS: usize = 4;
const MAX_OBJECTS: usize = 96;
/// The longest message, and what a client's requests are gathered in.
const IN: usize = 4096;
const MAX_FDS: usize = 8;
const MAX_SURFACES: usize = 8;
const MAX_BUFFERS: usize = 16;
const MAX_POOLS: usize = 8;
const MAX_FRAMES: usize = 4;

/// The globals, by name (their index + 1): interface and version.
const GLOBALS: [(&[u8], u32); 3] = [(b"wl_compositor", 4), (b"wl_shm", 1), (b"xdg_wm_base", 1)];

/// `wl_shm` formats: ARGB8888 and XRGB8888, which the screen's pixels are.
const ARGB8888: u32 = 0;
const XRGB8888: u32 = 1;

/// `wl_display.error` codes.
const INVALID_OBJECT: u32 = 0;
const INVALID_METHOD: u32 = 1;
const NO_MEMORY: u32 = 2;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Iface {
    None = 0,
    Display,
    Registry,
    Compositor,
    Region,
    Shm,
    Pool,
    Buffer,
    Surface,
    WmBase,
    Positioner,
    XdgSurface,
    Toplevel,
}

/// A client's object: its id, interface, and the table entry it is (a
/// pool's, buffer's or surface's index).
#[derive(Clone, Copy)]
struct Obj {
    id: u32,
    iface: Iface,
    data: u8,
}

struct Client {
    used: bool,
    /// The server's end of its connection (a Unix socket's index + 1).
    sock: u8,
    /// To be disconnected (its socket's buffer was full).
    dead: bool,
    objs: [Obj; MAX_OBJECTS],
    inb: [u8; IN],
    inlen: usize,
    /// Descriptors it sent, open files in order, for requests that take
    /// one.
    fds: [u8; MAX_FDS],
    nfds: usize,
}

#[derive(Clone, Copy)]
struct Pool {
    used: bool,
    client: u8,
    /// Destroyed by the client, kept while buffers use it.
    dead: bool,
    /// Its memory file (the open file's index).
    file: u8,
    size: u32,
}

#[derive(Clone, Copy)]
struct Buffer {
    used: bool,
    client: u8,
    id: u32,
    pool: u8,
    offset: u32,
    w: u32,
    h: u32,
    stride: u32,
}

#[derive(Clone, Copy)]
struct Surface {
    used: bool,
    client: u8,
    /// What `attach` asked for (a buffer's id, 0 none) and whether it did
    /// since the last commit.
    pending: u32,
    attached: bool,
    xdg: u32,
    toplevel: u32,
    configured: bool,
    /// Its window (its number + 1), size, and pages (shared pages from
    /// `first`).
    window: u8,
    w: u32,
    h: u32,
    first: u16,
    pages: u16,
    frames: [u32; MAX_FRAMES],
    nframes: usize,
}

pub struct Server {
    /// The listening socket (its index + 1), 0 if there is no server.
    listener: u8,
    serial: u32,
    /// Windows made so far, for where the next goes.
    made: u32,
    clients: [Client; MAX_CLIENTS],
    pools: [Pool; MAX_POOLS],
    buffers: [Buffer; MAX_BUFFERS],
    surfaces: [Surface; MAX_SURFACES],
}

const _: () = assert!(core::mem::size_of::<Server>() as u64 <= WL_PAGES * PAGE && WL_PAGES < SHM_PAGES);

fn server() -> &'static mut Server {
    // SAFETY: the first WL_PAGES shared pages, mapped here for this
    // server's life, zeroed at boot (an empty server) and kept from
    // memory files (`start`); only this one thread uses them, and no
    // reference outlives a call here.
    unsafe { &mut *(SHM_VA as *mut Server) }
}

/// Starts the server: keeps its pages and listens. Where there is a
/// compositor and shared memory only.
pub fn start(st: &mut State) {
    if !st.fb_pages || !st.shm_pages {
        return;
    }
    st.shm_take(0, WL_PAGES, true);
    let Ok(k) = unix_new(st, 0) else { return };
    let u = &mut st.unix[k];
    u.name[..SOCKET.len()].copy_from_slice(SOCKET);
    u.name_len = SOCKET.len() as u8;
    u.phase = unix::Phase::Listening;
    server().listener = k as u8 + 1;
}

/// A message being built: an object's event.
struct Msg {
    b: [u8; 512],
    n: usize,
}

impl Msg {
    fn new(id: u32, op: u16) -> Msg {
        let mut m = Msg { b: [0; 512], n: 8 };
        m.b[..4].copy_from_slice(&id.to_le_bytes());
        m.b[4..6].copy_from_slice(&op.to_le_bytes());
        m
    }
    fn u(mut self, v: u32) -> Msg {
        self.b[self.n..self.n + 4].copy_from_slice(&v.to_le_bytes());
        self.n += 4;
        self
    }
    fn s(mut self, t: &[u8]) -> Msg {
        self = self.u(t.len() as u32 + 1);
        self.b[self.n..self.n + t.len()].copy_from_slice(t);
        self.n += (t.len() + 1).next_multiple_of(4);
        self
    }
    /// An empty array.
    fn empty(self) -> Msg {
        self.u(0)
    }
}

/// Sends `m` to client `c`; a client whose buffer is full is cut off.
fn send(st: &mut State, sv: &mut Server, c: usize, mut m: Msg) {
    let cl = &mut sv.clients[c];
    let s = cl.sock as usize - 1;
    let n = m.n;
    m.b[6..8].copy_from_slice(&(n as u16).to_le_bytes());
    let p = st.unix[s].peer;
    if p == 0 || cl.dead {
        return;
    }
    let peer = &mut st.unix[p as usize - 1];
    if peer.room() < n || peer.put(&m.b[..n], None) != Some(n) {
        cl.dead = true;
    }
}

/// A request's arguments, read in order.
struct Args<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Args<'a> {
    fn u(&mut self) -> Result<u32, u32> {
        let v = self.b.get(self.at..self.at + 4).ok_or(INVALID_METHOD)?;
        self.at += 4;
        Ok(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
    }
    fn s(&mut self) -> Result<&'a [u8], u32> {
        let n = self.u()? as usize;
        let t = self.b.get(self.at..self.at + n).ok_or(INVALID_METHOD)?;
        self.at += n.next_multiple_of(4);
        Ok(&t[..n.saturating_sub(1)])
    }
}

/// Serves the clients: takes new ones, and their requests. Whether
/// anything was done (events sent).
pub fn service(st: &mut State) -> bool {
    let sv = server();
    if sv.listener == 0 {
        return false;
    }
    let mut moved = false;
    let l = sv.listener as usize - 1;
    while st.unix[l].nback > 0 {
        let u = &mut st.unix[l];
        let s = u.backlog[0] as usize - 1;
        u.backlog.copy_within(1.., 0);
        u.nback -= 1;
        match sv.clients.iter().position(|c| !c.used) {
            Some(c) => {
                let cl = &mut sv.clients[c];
                (cl.used, cl.sock, cl.dead, cl.inlen, cl.nfds) = (true, s as u8 + 1, false, 0, 0);
                cl.objs = [Obj { id: 0, iface: Iface::None, data: 0 }; MAX_OBJECTS];
                cl.objs[0] = Obj { id: 1, iface: Iface::Display, data: 0 };
            }
            None => st.unix_close(s),
        }
    }
    for c in 0..MAX_CLIENTS {
        if !sv.clients[c].used {
            continue;
        }
        let s = sv.clients[c].sock as usize - 1;
        // What it sent, and the descriptors with it.
        loop {
            let cl = &mut sv.clients[c];
            let (n, rights) = st.unix[s].take(&mut cl.inb[cl.inlen..]);
            cl.inlen += n;
            if let Some(r) = rights {
                for &f in &r.files[..r.n as usize] {
                    let cl = &mut sv.clients[c];
                    if cl.nfds < MAX_FDS {
                        cl.fds[cl.nfds] = f;
                        cl.nfds += 1;
                    } else {
                        st.release(f as usize);
                    }
                }
            }
            if n == 0 && rights.is_none() {
                break;
            }
        }
        // Its whole requests.
        while sv.clients[c].inlen >= 8 && !sv.clients[c].dead {
            let cl = &sv.clients[c];
            let w = |at: usize| u32::from_le_bytes([cl.inb[at], cl.inb[at + 1], cl.inb[at + 2], cl.inb[at + 3]]);
            let (id, word) = (w(0), w(4));
            let size = (word >> 16) as usize;
            if size < 8 || size % 4 != 0 {
                sv.clients[c].dead = true;
                break;
            }
            if cl.inlen < size {
                break;
            }
            let mut msg = [0u8; IN];
            msg[..size].copy_from_slice(&cl.inb[..size]);
            let cl = &mut sv.clients[c];
            cl.inb.copy_within(size..cl.inlen, 0);
            cl.inlen -= size;
            moved = true;
            if let Err((obj, code)) = request(st, sv, c, id, word as u16, &msg[8..size]) {
                send(st, sv, c, Msg::new(1, 0).u(obj).u(code).s(b"request refused"));
                sv.clients[c].dead = true;
            }
        }
        // Gone, or cut off.
        let u = &st.unix[s];
        if sv.clients[c].dead || u.eof && u.len == 0 {
            disconnect(st, sv, c);
            moved = true;
        }
    }
    moved
}

/// Client `c`'s object `id`: its index in the table.
fn find(sv: &Server, c: usize, id: u32) -> Option<usize> {
    sv.clients[c].objs.iter().position(|o| o.id == id && o.iface != Iface::None)
}

fn add(sv: &mut Server, c: usize, id: u32, iface: Iface, data: u8) -> Result<(), (u32, u32)> {
    let cl = &mut sv.clients[c];
    if id == 0 || cl.objs.iter().any(|o| o.id == id && o.iface != Iface::None) {
        return Err((1, INVALID_OBJECT));
    }
    let k = cl.objs.iter().position(|o| o.iface == Iface::None).ok_or((1, NO_MEMORY))?;
    cl.objs[k] = Obj { id, iface, data };
    Ok(())
}

/// Forgets object `id`, and tells the client it may use its id again.
fn remove(st: &mut State, sv: &mut Server, c: usize, id: u32) {
    if let Some(k) = find(sv, c, id) {
        sv.clients[c].objs[k].iface = Iface::None;
    }
    send(st, sv, c, Msg::new(1, 1).u(id));
}

/// The next descriptor client `c` sent.
fn take_fd(sv: &mut Server, c: usize) -> Option<usize> {
    let cl = &mut sv.clients[c];
    if cl.nfds == 0 {
        return None;
    }
    let f = cl.fds[0];
    cl.fds.copy_within(1.., 0);
    cl.nfds -= 1;
    Some(f as usize)
}

fn serial(sv: &mut Server) -> u32 {
    sv.serial = sv.serial.wrapping_add(1);
    sv.serial
}

/// Client `c`'s request `op` on object `id`; the object and error code it
/// is refused with.
fn request(st: &mut State, sv: &mut Server, c: usize, id: u32, op: u16, args: &[u8]) -> Result<(), (u32, u32)> {
    let k = find(sv, c, id).ok_or((id, INVALID_OBJECT))?;
    let Obj { iface, data, .. } = sv.clients[c].objs[k];
    let mut a = Args { b: args, at: 0 };
    let bad = |e: u32| (id, e);
    match (iface, op) {
        // wl_display.sync: done at once.
        (Iface::Display, 0) => {
            let cb = a.u().map_err(bad)?;
            let n = serial(sv);
            send(st, sv, c, Msg::new(cb, 0).u(n));
            send(st, sv, c, Msg::new(1, 1).u(cb));
        }
        // wl_display.get_registry: the globals.
        (Iface::Display, 1) => {
            let r = a.u().map_err(bad)?;
            add(sv, c, r, Iface::Registry, 0)?;
            for (n, (name, version)) in GLOBALS.iter().enumerate() {
                send(st, sv, c, Msg::new(r, 0).u(n as u32 + 1).s(name).u(*version));
            }
        }
        // wl_registry.bind(name, interface, version, id).
        (Iface::Registry, 0) => {
            let name = a.u().map_err(bad)?;
            let _ = a.s().map_err(bad)?;
            let _ = a.u().map_err(bad)?;
            let new = a.u().map_err(bad)?;
            let iface = match name {
                1 => Iface::Compositor,
                2 => Iface::Shm,
                3 => Iface::WmBase,
                _ => return Err(bad(INVALID_METHOD)),
            };
            add(sv, c, new, iface, 0)?;
            if iface == Iface::Shm {
                send(st, sv, c, Msg::new(new, 0).u(ARGB8888));
                send(st, sv, c, Msg::new(new, 0).u(XRGB8888));
            }
        }
        // wl_compositor.create_surface, create_region.
        (Iface::Compositor, 0) => {
            let new = a.u().map_err(bad)?;
            let s = sv.surfaces.iter().position(|s| !s.used).ok_or(bad(NO_MEMORY))?;
            add(sv, c, new, Iface::Surface, s as u8)?;
            sv.surfaces[s] = Surface {
                used: true,
                client: c as u8,
                pending: 0,
                attached: false,
                xdg: 0,
                toplevel: 0,
                configured: false,
                window: 0,
                w: 0,
                h: 0,
                first: 0,
                pages: 0,
                frames: [0; MAX_FRAMES],
                nframes: 0,
            };
        }
        (Iface::Compositor, 1) => add(sv, c, a.u().map_err(bad)?, Iface::Region, 0)?,
        // wl_region.destroy; its rectangles are not kept.
        (Iface::Region, 0) | (Iface::Positioner, 0) | (Iface::WmBase, 0) => remove(st, sv, c, id),
        (Iface::Region, _) | (Iface::Positioner, _) => {}
        // wl_shm.create_pool(id, fd, size).
        (Iface::Shm, 0) => {
            let new = a.u().map_err(bad)?;
            let size = a.u().map_err(bad)?;
            let f = take_fd(sv, c).ok_or(bad(INVALID_METHOD))?;
            let o = st.files[f];
            let ok = o.kind == FileKind::Shm && size as u64 <= st.shm[o.pipe as usize].size;
            let p = sv.pools.iter().position(|p| !p.used);
            match (ok, p) {
                (true, Some(p)) => {
                    sv.pools[p] = Pool { used: true, client: c as u8, dead: false, file: f as u8, size };
                    add(sv, c, new, Iface::Pool, p as u8)?;
                }
                _ => {
                    st.release(f);
                    return Err(bad(if ok { NO_MEMORY } else { INVALID_METHOD }));
                }
            }
        }
        // wl_shm_pool.create_buffer(id, offset, width, height, stride,
        // format), destroy, resize.
        (Iface::Pool, 0) => {
            let new = a.u().map_err(bad)?;
            let [offset, w, h, stride, format] = [a.u(), a.u(), a.u(), a.u(), a.u()].map(|v| v.unwrap_or(u32::MAX));
            let pool = sv.pools[data as usize];
            let end = (offset as u64).saturating_add(stride as u64 * h as u64);
            if format > XRGB8888 || w == 0 || h == 0 || (stride as u64) < w as u64 * 4 || end > pool.size as u64 {
                return Err(bad(INVALID_METHOD));
            }
            let b = sv.buffers.iter().position(|b| !b.used).ok_or(bad(NO_MEMORY))?;
            sv.buffers[b] = Buffer { used: true, client: c as u8, id: new, pool: data, offset, w, h, stride };
            add(sv, c, new, Iface::Buffer, b as u8)?;
        }
        (Iface::Pool, 1) => {
            sv.pools[data as usize].dead = true;
            remove(st, sv, c, id);
            pool_sweep(st, sv);
        }
        (Iface::Pool, 2) => {
            let size = a.u().map_err(bad)?;
            let p = &mut sv.pools[data as usize];
            if (size as u64) > st.shm[st.files[p.file as usize].pipe as usize].size {
                return Err(bad(INVALID_METHOD));
            }
            p.size = p.size.max(size);
        }
        // wl_buffer.destroy.
        (Iface::Buffer, 0) => {
            sv.buffers[data as usize].used = false;
            remove(st, sv, c, id);
            pool_sweep(st, sv);
        }
        // wl_surface: destroy, attach, frame, commit; the rest taken.
        (Iface::Surface, 0) => {
            unshow(sv, data as usize);
            sv.surfaces[data as usize].used = false;
            remove(st, sv, c, id);
        }
        (Iface::Surface, 1) => {
            let s = &mut sv.surfaces[data as usize];
            s.pending = a.u().map_err(bad)?;
            s.attached = true;
        }
        (Iface::Surface, 3) => {
            let cb = a.u().map_err(bad)?;
            let s = &mut sv.surfaces[data as usize];
            if s.nframes == MAX_FRAMES {
                return Err(bad(NO_MEMORY));
            }
            s.frames[s.nframes] = cb;
            s.nframes += 1;
        }
        (Iface::Surface, 6) => commit(st, sv, c, data as usize),
        (Iface::Surface, _) => {}
        // xdg_wm_base: create_positioner, get_xdg_surface, pong.
        (Iface::WmBase, 1) => add(sv, c, a.u().map_err(bad)?, Iface::Positioner, 0)?,
        (Iface::WmBase, 2) => {
            let new = a.u().map_err(bad)?;
            let surf = a.u().map_err(bad)?;
            let k = find(sv, c, surf).filter(|&k| sv.clients[c].objs[k].iface == Iface::Surface).ok_or(bad(INVALID_OBJECT))?;
            let s = sv.clients[c].objs[k].data;
            add(sv, c, new, Iface::XdgSurface, s)?;
            sv.surfaces[s as usize].xdg = new;
        }
        (Iface::WmBase, 3) => {}
        // xdg_surface: destroy, get_toplevel (configured at once: any
        // size, no states), ack_configure; popups are not served.
        (Iface::XdgSurface, 0) => {
            sv.surfaces[data as usize].xdg = 0;
            remove(st, sv, c, id);
        }
        (Iface::XdgSurface, 1) => {
            let new = a.u().map_err(bad)?;
            add(sv, c, new, Iface::Toplevel, data)?;
            sv.surfaces[data as usize].toplevel = new;
            let xdg = sv.surfaces[data as usize].xdg;
            send(st, sv, c, Msg::new(new, 0).u(0).u(0).empty());
            let n = serial(sv);
            send(st, sv, c, Msg::new(xdg, 0).u(n));
        }
        (Iface::XdgSurface, 4) => sv.surfaces[data as usize].configured = true,
        (Iface::XdgSurface, _) => {}
        // xdg_toplevel.destroy: its window goes; set_title; the rest taken.
        (Iface::Toplevel, 0) => {
            unshow(sv, data as usize);
            sv.surfaces[data as usize].toplevel = 0;
            remove(st, sv, c, id);
        }
        (Iface::Toplevel, 2) => {
            let t = a.s().map_err(bad)?;
            let s = sv.surfaces[data as usize];
            if s.window != 0 {
                let mut b = [0u8; 16];
                let n = t.len().min(16);
                b[..n].copy_from_slice(&t[..n]);
                let w = |k: usize| u64::from_le_bytes([b[k], b[k + 1], b[k + 2], b[k + 3], b[k + 4], b[k + 5], b[k + 6], b[k + 7]]);
                let _ = fb_call(window::set_title(s.window as u64 - 1, w(0), w(8)), None);
            }
        }
        (Iface::Toplevel, _) => {}
        _ => return Err(bad(INVALID_METHOD)),
    }
    Ok(())
}

/// Gives back the pools destroyed that no buffer uses.
fn pool_sweep(st: &mut State, sv: &mut Server) {
    for p in 0..MAX_POOLS {
        let pool = sv.pools[p];
        if pool.used && pool.dead && !sv.buffers.iter().any(|b| b.used && b.pool as usize == p) {
            sv.pools[p].used = false;
            st.release(pool.file as usize);
        }
    }
}

/// Takes surface `s`'s window off the screen and gives its pages back.
fn unshow(sv: &mut Server, s: usize) {
    let sf = &mut sv.surfaces[s];
    if sf.window != 0 {
        let _ = fb_call(window::destroy(sf.window as u64 - 1), None);
        sf.window = 0;
    }
}

/// Commits surface `s`: the buffer attached shown in its toplevel's
/// window (made, or remade at a new size); frame callbacks done.
fn commit(st: &mut State, sv: &mut Server, c: usize, s: usize) {
    let sf = sv.surfaces[s];
    if sf.attached && sf.toplevel != 0 && sf.configured {
        let buffer = find(sv, c, sf.pending)
            .filter(|&k| sv.clients[c].objs[k].iface == Iface::Buffer)
            .map(|k| sv.clients[c].objs[k].data as usize);
        match buffer {
            None => unshow_free(st, sv, s),
            Some(b) => {
                let buf = sv.buffers[b];
                if show(st, sv, s, buf).is_ok() {
                    send(st, sv, c, Msg::new(buf.id, 0));
                }
            }
        }
    }
    let sf = &mut sv.surfaces[s];
    sf.attached = false;
    let (frames, n) = (sf.frames, sf.nframes);
    sf.nframes = 0;
    let ms = (superior_sys::ticks() * 1000 / TICK_HZ) as u32;
    for &cb in &frames[..n] {
        send(st, sv, c, Msg::new(cb, 0).u(ms));
        send(st, sv, c, Msg::new(1, 1).u(cb));
    }
}

/// Surface `s`'s window gone, and its pages free.
fn unshow_free(st: &mut State, sv: &mut Server, s: usize) {
    unshow(sv, s);
    let sf = &mut sv.surfaces[s];
    if sf.pages != 0 {
        st.shm_take(sf.first as u64, sf.pages as u64, false);
        sf.pages = 0;
    }
}

/// Shows buffer `b` in surface `s`'s window.
fn show(st: &mut State, sv: &mut Server, s: usize, b: Buffer) -> Result<(), u64> {
    if sv.surfaces[s].window == 0 || (sv.surfaces[s].w, sv.surfaces[s].h) != (b.w, b.h) {
        unshow_free(st, sv, s);
        let pages = (b.w as u64 * b.h as u64 * 4).div_ceil(PAGE);
        if pages > window::WINDOW_PAGES {
            return Err(EINVAL);
        }
        let first = (0..SHM_PAGES).find(|&p| st.shm_free(p, pages)).ok_or(ENOMEM)?;
        st.shm_take(first, pages, true);
        let sf = &mut sv.surfaces[s];
        (sf.first, sf.pages, sf.w, sf.h) = (first as u16, pages as u16, b.w, b.h);
        // Placed down and right of the last, on the screen.
        let k = sv.made as u64 % 8;
        let (x, y) = (40 + 30 * k, 40 + 30 * k);
        let ok = |m: Option<[u64; 4]>| m.filter(|m| m[0] == 0);
        let n = ok(fb_call(window::create(b.w as u64 | (b.h as u64) << 16, x | y << 16), None))
            .or_else(|| ok(fb_call(window::create(b.w as u64 | (b.h as u64) << 16, 0), None)))
            .ok_or(ENOMEM)?[1];
        if !(0..pages).all(|p| ok(fb_call(window::attach(n, p), Some(SHM_SLOTS + first + p))).is_some()) {
            let _ = fb_call(window::destroy(n), None);
            st.shm_take(first, pages, false);
            sv.surfaces[s].pages = 0;
            return Err(ENOMEM);
        }
        let _ = fb_call(window::listen(n), Some(crate::NTFN_WINDOW));
        sv.surfaces[s].window = n as u8 + 1;
        sv.made += 1;
    }
    let sf = sv.surfaces[s];
    let pool = sv.pools[b.pool as usize];
    let shm = st.shm[st.files[pool.file as usize].pipe as usize];
    if b.offset as u64 + b.stride as u64 * b.h as u64 > shm.size {
        return Err(EINVAL);
    }
    let from = SHM_VA + shm.first as u64 * PAGE + b.offset as u64;
    let to = SHM_VA + sf.first as u64 * PAGE;
    let row = b.w as usize * 4;
    for y in 0..b.h as u64 {
        // SAFETY: shared pages, mapped here: the row lies within the
        // pool's memory file (checked above) and within the window's
        // pages (w * h * 4 bytes of them).
        unsafe { core::ptr::copy_nonoverlapping((from + y * b.stride as u64) as *const u8, (to + y * row as u64) as *mut u8, row) };
    }
    let rect = (b.w as u64) << 32 | (b.h as u64) << 48;
    let _ = fb_call(window::commit(sf.window as u64 - 1, rect), None);
    Ok(())
}

/// Client `c` gone: its windows, buffers and pools with it.
fn disconnect(st: &mut State, sv: &mut Server, c: usize) {
    for s in 0..MAX_SURFACES {
        if sv.surfaces[s].used && sv.surfaces[s].client as usize == c {
            unshow_free(st, sv, s);
            sv.surfaces[s].used = false;
        }
    }
    for b in sv.buffers.iter_mut().filter(|b| b.used && b.client as usize == c) {
        b.used = false;
    }
    for p in sv.pools.iter_mut().filter(|p| p.used && p.client as usize == c) {
        p.dead = true;
    }
    pool_sweep(st, sv);
    while let Some(f) = take_fd(sv, c) {
        st.release(f);
    }
    let cl = &mut sv.clients[c];
    cl.used = false;
    st.unix_close(cl.sock as usize - 1);
}

/// The toplevels' windows' events: the close box closes the toplevel.
pub fn window_events(st: &mut State) {
    let sv = server();
    for s in 0..MAX_SURFACES {
        let sf = sv.surfaces[s];
        if !sf.used || sf.window == 0 {
            continue;
        }
        while let Some(m) = fb_call(window::next(sf.window as u64 - 1), None).filter(|m| m[0] == 0) {
            if m[1] == window::CLOSE && sf.toplevel != 0 {
                send(st, sv, sf.client as usize, Msg::new(sf.toplevel, 1));
            }
        }
    }
}
