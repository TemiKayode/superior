// Generated from interfaces/display.idl by the IDL compiler (`cargo xtask idl`).
// Do not edit: change the description and generate again.

/// A display: what a display driver serves. The caller draws into a
/// surface of its own pages, lent to the driver a page at a time, and asks
/// for rectangles of it to be shown; the driver copies them into the
/// framebuffer it is not showing and flips to it, so the screen changes
/// whole. Pixels are XRGB8888, 32 bits each (blue in the low byte), rows
/// `pitch` bytes apart, in the surface as on the screen.
///
/// A display may have a cursor plane (version 2): a small picture it shows
/// over the screen, moved without the caller drawing it into the surface
/// or flushing anything. One without answers `CURSOR` with `Invalid`, and
/// the caller draws its pointer itself.
pub mod display {
    use crate::interfaces::Status;

    pub const VERSION: u64 = 2;

    /// The most surface pages a caller may attach (4 MiB: 1024x768 at 32
    /// bits).
    pub const SURFACE_PAGES: u64 = 1024;

    /// A cursor's picture: CURSOR_SIDE pixels square, ARGB8888 (the top byte
    /// its opacity), rows CURSOR_SIDE * 4 bytes apart: one page.
    pub const CURSOR_SIDE: u64 = 32;

    /// What the display offers: how many modes (`MODE` lists them, preferred
    /// first), which of them is preferred, and whether the display's EDID was
    /// read (the modes are then the display's own).
    pub const INFO: u64 = 1;
    /// The message of a `INFO` call.
    pub const fn info() -> [u64; 4] {
        [INFO, VERSION, 0, 0]
    }
    /// What a `INFO` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct InfoReply {
        pub modes: u64,
        pub preferred: u64,
        pub edid: u64,
    }
    /// Reads a `INFO` reply: its results, or the status it failed with.
    pub fn info_reply(m: [u64; 4]) -> Result<InfoReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(InfoReply {
                modes: m[1],
                preferred: m[2],
                edid: m[3],
            }),
            s => Err(s),
        }
    }

    /// Mode `index`: its size in pixels and refresh rate in Hz.
    pub const MODE: u64 = 2;
    /// The message of a `MODE` call.
    pub const fn mode(index: u64) -> [u64; 4] {
        [MODE, index, 0, 0]
    }
    /// What a `MODE` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ModeReply {
        pub width: u64,
        pub height: u64,
        pub refresh: u64,
    }
    /// Reads a `MODE` reply: its results, or the status it failed with.
    pub fn mode_reply(m: [u64; 4]) -> Result<ModeReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(ModeReply {
                width: m[1],
                height: m[2],
                refresh: m[3],
            }),
            s => Err(s),
        }
    }

    /// Keeps page `page` of the caller's surface, which the call lends. Pages
    /// come in order from 0; attaching page 0 again starts a new surface.
    pub const ATTACH: u64 = 3;
    /// The message of a `ATTACH` call.
    pub const fn attach(page: u64) -> [u64; 4] {
        [ATTACH, page, 0, 0]
    }

    /// Shows mode `index`, cleared to black, once enough of the surface is
    /// attached for it (`pitch` times its height). Returns the pitch in bytes
    /// and where the two framebuffers lie in video memory.
    pub const SET_MODE: u64 = 4;
    /// The message of a `SET_MODE` call.
    pub const fn set_mode(index: u64) -> [u64; 4] {
        [SET_MODE, index, 0, 0]
    }
    /// What a `SET_MODE` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SetModeReply {
        pub pitch: u64,
        pub front_offset: u64,
        pub back_offset: u64,
    }
    /// Reads a `SET_MODE` reply: its results, or the status it failed with.
    pub fn set_mode_reply(m: [u64; 4]) -> Result<SetModeReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(SetModeReply {
                pitch: m[1],
                front_offset: m[2],
                back_offset: m[3],
            }),
            s => Err(s),
        }
    }

    /// Shows the surface's rectangle `rect` (x | y << 16 | width << 32 |
    /// height << 48, in pixels): copied into the hidden framebuffer, which is
    /// then flipped to. Returns which framebuffer is shown now and how many
    /// flips there have been.
    pub const FLUSH: u64 = 5;
    /// The message of a `FLUSH` call.
    pub const fn flush(rect: u64) -> [u64; 4] {
        [FLUSH, rect, 0, 0]
    }
    /// What a `FLUSH` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FlushReply {
        pub front: u64,
        pub flips: u64,
    }
    /// Reads a `FLUSH` reply: its results, or the status it failed with.
    pub fn flush_reply(m: [u64; 4]) -> Result<FlushReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(FlushReply {
                front: m[1],
                flips: m[2],
            }),
            s => Err(s),
        }
    }

    /// Takes the cursor's picture from the page the call lends (kept no longer
    /// than the call), its point `hot` (x | y << 16, in the picture): shown
    /// there once `MOVE_CURSOR` shows it. `Invalid` if the display has no
    /// cursor plane.
    pub const CURSOR: u64 = 6;
    /// The message of a `CURSOR` call.
    pub const fn cursor(hot: u64) -> [u64; 4] {
        [CURSOR, hot, 0, 0]
    }

    /// Puts the cursor's point at (`x`, `y`) on the screen, shown if `shown` is
    /// 1 and hidden if 0. Returns how many moves there have been.
    pub const MOVE_CURSOR: u64 = 7;
    /// The message of a `MOVE_CURSOR` call.
    pub const fn move_cursor(x: u64, y: u64, shown: u64) -> [u64; 4] {
        [MOVE_CURSOR, x, y, shown]
    }
    /// What a `MOVE_CURSOR` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MoveCursorReply {
        pub moves: u64,
    }
    /// Reads a `MOVE_CURSOR` reply: its results, or the status it failed with.
    pub fn move_cursor_reply(m: [u64; 4]) -> Result<MoveCursorReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(MoveCursorReply {
                moves: m[1],
            }),
            s => Err(s),
        }
    }
}
