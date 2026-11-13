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
///
/// Input: the compositor draws the pointer over everything once it first
/// moves. The window under it gets pointer events; pressing a button over
/// a window gives it the keyboard focus, puts it in front and holds the
/// pointer to it (it keeps getting pointer events, wherever the pointer
/// goes) until every button is let go. The wheel turns for the window the
/// pointer events go to. Keys go to the window with the
/// focus; a newly shown window takes it, and when the window with it goes
/// the front window gets it. Each window keeps its events until its client
/// reads them (`NEXT`), and signals the notification its client lent with
/// `LISTEN` when one arrives.
///
/// Style (`STYLE`): a window may be translucent, its pixels' top byte
/// then saying how opaque each is (0 not at all, 255 wholly), blended
/// over what is behind it; and decorated, the compositor then drawing a
/// border and a title bar with a close box around it, outside its
/// pixels. A button pressed on the title bar gives the window the focus,
/// puts it in front and drags it with the pointer until let go (it is
/// told where it ended, `MOVED`); one pressed on the close box asks its
/// client to close it (`CLOSE`). The window's position is still its own
/// pixels' top left; its frame must lie wholly on the screen. A decorated
/// window's title (`SET_TITLE`) is drawn in its title bar.
///
/// The desktop shell: a client whose capability is a manager's (`manages
/// window` in its manifest, its badge marked `MANAGER_BADGE`) may list,
/// describe and activate every client's windows, and its own windows are
/// told when they change (`WINDOWS`). Its windows stay in front of every
/// other client's and never take the keyboard focus. Anyone else asking
/// is `Denied`.
pub mod window {
    use crate::interfaces::Status;

    pub const VERSION: u64 = 6;

    /// The most windows on the screen, all clients together.
    pub const MAX_WINDOWS: u64 = 8;

    /// The most pages one window may have (1.5 MiB: 640x600 at 32 bits).
    pub const WINDOW_PAGES: u64 = 384;

    /// The kinds of event `NEXT` gives, and what `a` and `b` say.
    /// A key went down or up while the window had the focus: `a` is its USB
    /// HID usage, `b` is 1 if pressed and 0 if released, with the modifier
    /// byte in bits 8 to 15.
    pub const KEY: u64 = 1;

    /// The pointer moved over the window (or anywhere, while it is held to the
    /// window), or a button went down or up: `a` is where it is in the window
    /// (x | y << 16, each a signed 16-bit number, negative off its left or
    /// top), `b` the buttons held (bit 0 left, 1 right, 2 middle, then any
    /// others the pointing device has, up to bit 7).
    pub const POINTER: u64 = 2;

    /// The window got the keyboard focus (`a` 1) or lost it (`a` 0).
    pub const FOCUS: u64 = 3;

    /// The pointer left the window.
    pub const LEAVE: u64 = 4;

    /// The wheel turned while the pointer's events went to the window: `a` is
    /// where the pointer is (as for `POINTER`), `b` how far: up (away from the
    /// user) in bits 0 to 31 and right in bits 32 to 63, each a signed 32-bit
    /// number of steps.
    pub const WHEEL: u64 = 5;

    /// A button was pressed on the window's close box: its client should
    /// close it.
    pub const CLOSE: u64 = 6;

    /// The window was dragged by its title bar: `a` is where it is now (x |
    /// y << 16 on the screen).
    pub const MOVED: u64 = 7;

    /// To a manager's windows: the windows shown, their titles or the focus
    /// changed.
    pub const WINDOWS: u64 = 8;

    /// Events a window keeps until they are read; past that the oldest go.
    pub const EVENTS: u64 = 32;

    /// The flags `STYLE` takes.
    /// The window's pixels' top byte is how opaque each is.
    pub const ALPHA: u64 = 1;

    /// The compositor draws a border and a title bar around the window.
    pub const DECORATED: u64 = 2;

    /// A decorated window's frame: the border's width all round, the title
    /// bar's height between the top border and the window, and its close box,
    /// a square at the title bar's right end that far from its top, bottom and
    /// right.
    pub const BORDER: u64 = 2;

    pub const TITLE: u64 = 18;

    pub const CLOSE_BOX: u64 = 12;

    pub const CLOSE_MARGIN: u64 = 3;

    /// The most bytes of a window's title.
    pub const TITLE_BYTES: u64 = 16;

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

    /// Has the compositor signal the notification the call lends whenever an
    /// event for the window arrives (in place of one lent before).
    pub const LISTEN: u64 = 8;
    /// The message of a `LISTEN` call.
    pub const fn listen(window: u64) -> [u64; 4] {
        [LISTEN, window, 0, 0]
    }

    /// The window's oldest event not yet read: its kind and what it says.
    /// `Empty` if there is none.
    pub const NEXT: u64 = 9;
    /// The message of a `NEXT` call.
    pub const fn next(window: u64) -> [u64; 4] {
        [NEXT, window, 0, 0]
    }
    /// What a `NEXT` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct NextReply {
        pub kind: u64,
        pub a: u64,
        pub b: u64,
    }
    /// Reads a `NEXT` reply: its results, or the status it failed with.
    pub fn next_reply(m: [u64; 4]) -> Result<NextReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(NextReply {
                kind: m[1],
                a: m[2],
                b: m[3],
            }),
            s => Err(s),
        }
    }

    /// Sets the window's style: `flags` of `ALPHA` and `DECORATED`. `Invalid`
    /// for other flags, or if the frame it would have does not lie wholly on
    /// the screen.
    pub const STYLE: u64 = 10;
    /// The message of a `STYLE` call.
    pub const fn style(window: u64, flags: u64) -> [u64; 4] {
        [STYLE, window, flags, 0]
    }

    /// Sets the window's title: up to `TITLE_BYTES` of ASCII, `a` the first 8
    /// (the first in its low byte) and `b` the next, a zero byte ending it
    /// early. A decorated window shows as much of it as fits before its close
    /// box.
    pub const SET_TITLE: u64 = 11;
    /// The message of a `SET_TITLE` call.
    pub const fn set_title(window: u64, a: u64, b: u64) -> [u64; 4] {
        [SET_TITLE, window, a, b]
    }

    /// A manager's: the windows shown (bit n for window n) and the one with
    /// the keyboard focus (`MAX_WINDOWS` if none).
    pub const LIST: u64 = 12;
    /// The message of a `LIST` call.
    pub const fn list() -> [u64; 4] {
        [LIST, 0, 0, 0]
    }
    /// What a `LIST` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ListReply {
        pub shown: u64,
        pub focus: u64,
    }
    /// Reads a `LIST` reply: its results, or the status it failed with.
    pub fn list_reply(m: [u64; 4]) -> Result<ListReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(ListReply {
                shown: m[1],
                focus: m[2],
            }),
            s => Err(s),
        }
    }

    /// A manager's: window `window`'s title (as `SET_TITLE` takes it) and
    /// whether it is a manager's own (bit 0 of `flags`).
    pub const DESCRIBE: u64 = 13;
    /// The message of a `DESCRIBE` call.
    pub const fn describe(window: u64) -> [u64; 4] {
        [DESCRIBE, window, 0, 0]
    }
    /// What a `DESCRIBE` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DescribeReply {
        pub a: u64,
        pub b: u64,
        pub flags: u64,
    }
    /// Reads a `DESCRIBE` reply: its results, or the status it failed with.
    pub fn describe_reply(m: [u64; 4]) -> Result<DescribeReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(DescribeReply {
                a: m[1],
                b: m[2],
                flags: m[3],
            }),
            s => Err(s),
        }
    }

    /// A manager's: puts window `window` in front of every other client's and
    /// gives it the keyboard focus.
    pub const ACTIVATE: u64 = 14;
    /// The message of a `ACTIVATE` call.
    pub const fn activate(window: u64) -> [u64; 4] {
        [ACTIVATE, window, 0, 0]
    }
}
