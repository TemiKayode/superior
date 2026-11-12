// Generated from interfaces/window.idl by the IDL compiler (`cargo xtask idl`).
// Do not edit: change the description and generate again.

/// Windows: what the compositor serves. A client draws a window into pages
/// of its own, lends them to the compositor a page at a time and asks for
/// rectangles of it to be shown; the compositor puts every client's
/// windows together over the desktop, front to back, and has the display
/// driver show the result. Pixels are XRGB8888, 32 bits each, rows the
/// window's width times 4 bytes apart. A client sees and changes only its
/// own windows (the capability's badge says whose); a window goes when its
/// client does. Crash-only: when the compositor restarts, calls fail once
/// with `PeerRestarted` and the client makes its windows again.
pub mod window {
    use crate::interfaces::Status;

    pub const VERSION: u64 = 1;

    /// The most windows on the screen, all clients together.
    pub const MAX_WINDOWS: u64 = 8;

    /// The most pages one window may have (1.5 MiB: 640x600 at 32 bits).
    pub const WINDOW_PAGES: u64 = 384;

    /// The screen's size, and how many windows are shown on it (every
    /// client's).
    pub const INFO: u64 = 1;
    /// The message of a `INFO` call.
    pub const fn info() -> [u64; 4] {
        [INFO, VERSION, 0, 0]
    }
    /// What a `INFO` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct InfoReply {
        pub width: u64,
        pub height: u64,
        pub shown: u64,
    }
    /// Reads a `INFO` reply: its results, or the status it failed with.
    pub fn info_reply(m: [u64; 4]) -> Result<InfoReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(InfoReply {
                width: m[1],
                height: m[2],
                shown: m[3],
            }),
            s => Err(s),
        }
    }

    /// Makes a window `size` (width | height << 16) at `position` (x | y << 16
    /// on the screen), which must lie wholly on the screen. It is hidden until
    /// its first `COMMIT`. `InUse` if there are `MAX_WINDOWS` already.
    pub const CREATE: u64 = 2;
    /// The message of a `CREATE` call.
    pub const fn create(size: u64, position: u64) -> [u64; 4] {
        [CREATE, size, position, 0]
    }
    /// What a `CREATE` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CreateReply {
        pub window: u64,
    }
    /// Reads a `CREATE` reply: its results, or the status it failed with.
    pub fn create_reply(m: [u64; 4]) -> Result<CreateReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(CreateReply {
                window: m[1],
            }),
            s => Err(s),
        }
    }

    /// Keeps page `page` of window `window`, which the call lends. Pages come
    /// in order from 0.
    pub const ATTACH: u64 = 3;
    /// The message of a `ATTACH` call.
    pub const fn attach(window: u64, page: u64) -> [u64; 4] {
        [ATTACH, window, page, 0]
    }

    /// Shows the window's rectangle `rect` (x | y << 16 | width << 32 | height
    /// << 48, in the window's pixels), once all its pages are attached. The
    /// first commit shows the window, in front of every other. Returns how
    /// many times the screen has changed.
    pub const COMMIT: u64 = 4;
    /// The message of a `COMMIT` call.
    pub const fn commit(window: u64, rect: u64) -> [u64; 4] {
        [COMMIT, window, rect, 0]
    }
    /// What a `COMMIT` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CommitReply {
        pub frames: u64,
    }
    /// Reads a `COMMIT` reply: its results, or the status it failed with.
    pub fn commit_reply(m: [u64; 4]) -> Result<CommitReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(CommitReply {
                frames: m[1],
            }),
            s => Err(s),
        }
    }

    /// Moves the window to `position` (x | y << 16), wholly on the screen. A
    /// move to where it is changes nothing, so a client can ask whether the
    /// compositor still has its window.
    pub const MOVE_TO: u64 = 5;
    /// The message of a `MOVE_TO` call.
    pub const fn move_to(window: u64, position: u64) -> [u64; 4] {
        [MOVE_TO, window, position, 0]
    }

    /// Puts the window in front of every other.
    pub const RAISE: u64 = 6;
    /// The message of a `RAISE` call.
    pub const fn raise(window: u64) -> [u64; 4] {
        [RAISE, window, 0, 0]
    }

    /// Takes the window off the screen and gives its pages back.
    pub const DESTROY: u64 = 7;
    /// The message of a `DESTROY` call.
    pub const fn destroy(window: u64) -> [u64; 4] {
        [DESTROY, window, 0, 0]
    }
}
