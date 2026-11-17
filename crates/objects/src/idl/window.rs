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
///
/// Resizing: a resizable window's client may lend more pages than its size
/// needs (up to `WINDOW_PAGES`). A button pressed on any of its borders
/// (the top one is the strip above the title bar), or a corner between
/// two, drags an outline of the size asked for; let go, the client is told
/// (`RESIZE`), draws at the size it accepts and sets it (`SET_SIZE`), so
/// it is never shown at a width its pixels were not drawn for. If its left
/// or top border was dragged, the size it sets is taken from its right or
/// bottom edge, which stay where they were: the window moves, and is told
/// where to (`MOVED`).
///
/// Maximising: a resizable decorated window has a maximise box between its
/// close and minimise boxes. Pressed, its client is asked (`RESIZE`) for
/// the size that fills the screen above any manager's windows along the
/// screen's bottom (the panel), the frame within that; the size it sets
/// is taken with the window moved to that space's top left (it is told,
/// `MOVED`). Pressed again, the client is asked for the size it had, and
/// the window goes back where it was.
///
/// Icons: a client may say what its window is (`SET_ICON`), a number the
/// desktop shell draws a picture for, and a manager may ask (`ICON`).
///
/// The clipboard (`CLIP_PUT`, `CLIP_GET`): text copied in one app to be
/// pasted in any other. Only the client of the window with the keyboard
/// focus may put text there or read it, so an app in the background can
/// neither read what the user copied nor change it. A restarted
/// compositor's clipboard is empty.
///
/// Key repeat: a key held (not a modifier) is pressed again for the window
/// with the focus every `REPEAT_INTERVAL` ms once it has been held
/// `REPEAT_DELAY` ms, until it is let go, another key is pressed or the
/// focus moves.
pub mod window {
    use crate::interfaces::Status;

    pub const VERSION: u64 = 11;

    /// The most windows on the screen, all clients together.
    pub const MAX_WINDOWS: u64 = 8;

    /// The most pages one window may have (1.5 MiB: 640x600 at 32 bits).
    pub const WINDOW_PAGES: u64 = 384;

    /// The kinds of event `NEXT` gives, and what `a` and `b` say.
    /// A key went down or up while the window had the focus: `a` is its USB
    /// HID usage, `b` is 1 if pressed and 0 if released (3 if pressed again
    /// by key repeat), with the modifier byte in bits 8 to 15.
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

    /// The window was dragged by its title bar, or moved by a resize or a
    /// maximise: `a` is where it is now (x | y << 16 on the screen).
    pub const MOVED: u64 = 7;

    /// To a manager's windows: the windows shown, their titles or the focus
    /// changed.
    pub const WINDOWS: u64 = 8;

    /// The user dragged the window's frame to ask for a size: `a` is width |
    /// height << 16. The client draws at the size it accepts and sets it.
    pub const RESIZE: u64 = 9;

    /// Events a window keeps until they are read; past that the oldest go.
    pub const EVENTS: u64 = 32;

    /// The flags `STYLE` takes.
    /// The window's pixels' top byte is how opaque each is.
    pub const ALPHA: u64 = 1;

    /// The compositor draws a border and a title bar around the window.
    pub const DECORATED: u64 = 2;

    /// The window's borders may be dragged to resize it.
    pub const RESIZABLE: u64 = 4;

    /// The smallest size a drag asks for.
    pub const MIN_WIDTH: u64 = 64;

    pub const MIN_HEIGHT: u64 = 32;

    /// A decorated window's frame: the border's width all round, the title
    /// bar's height between the top border and the window, and its close box,
    /// a square at the title bar's right end that far from its top, bottom and
    /// right. A resizable window's maximise box is the same square, that far
    /// left of the close box; its minimise box (any window's) is the same
    /// square again, that far left of the box before it: pressed, the window
    /// is minimised (see `MINIMISE`).
    pub const BORDER: u64 = 2;

    pub const TITLE: u64 = 18;

    pub const CLOSE_BOX: u64 = 12;

    pub const CLOSE_MARGIN: u64 = 3;

    /// The most bytes of a window's title.
    pub const TITLE_BYTES: u64 = 16;

    /// The most bytes the clipboard holds.
    pub const CLIPBOARD_BYTES: u64 = 32;

    /// How long a key is held before it repeats, and how often it does then,
    /// in milliseconds.
    pub const REPEAT_DELAY: u64 = 500;

    pub const REPEAT_INTERVAL: u64 = 50;

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
    /// in order from 0, up to `WINDOW_PAGES`: more than its size needs leaves
    /// room to grow.
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

    /// Sets the window's style: `flags` of `ALPHA`, `DECORATED` and `RESIZABLE`. `Invalid`
    /// for other flags, or if the frame it would have does not lie wholly on
    /// the screen.
    pub const STYLE: u64 = 10;
    /// The message of a `STYLE` call.
    pub const fn style(window: u64, flags: u64) -> [u64; 4] {
        [STYLE, window, flags, 0]
    }

    /// Sets the window's title: up to `TITLE_BYTES` of ASCII, `a` the first 8
    /// (the first in its low byte) and `b` the next, a zero byte ending it
    /// early. A decorated window shows as much of it as fits before its
    /// boxes.
    pub const SET_TITLE: u64 = 11;
    /// The message of a `SET_TITLE` call.
    pub const fn set_title(window: u64, a: u64, b: u64) -> [u64; 4] {
        [SET_TITLE, window, a, b]
    }

    /// A manager's: the windows shown (bit n for window n), the one with the
    /// keyboard focus (`MAX_WINDOWS` if none) and those of them minimised.
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
        pub minimised: u64,
    }
    /// Reads a `LIST` reply: its results, or the status it failed with.
    pub fn list_reply(m: [u64; 4]) -> Result<ListReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(ListReply {
                shown: m[1],
                focus: m[2],
                minimised: m[3],
            }),
            s => Err(s),
        }
    }

    /// A manager's: window `window`'s title (as `SET_TITLE` takes it) and
    /// whether it is a manager's own (bit 0 of `flags`), minimised (bit 1) or
    /// maximised (bit 2).
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
    /// gives it the keyboard focus (if minimised, it is drawn again).
    pub const ACTIVATE: u64 = 14;
    /// The message of a `ACTIVATE` call.
    pub const fn activate(window: u64) -> [u64; 4] {
        [ACTIVATE, window, 0, 0]
    }

    /// Makes the window `size` (width | height << 16): its pixels' rows are
    /// then the new width apart. `Invalid` if it would need more pages than
    /// were attached, or would not lie wholly on the screen.
    pub const SET_SIZE: u64 = 15;
    /// The message of a `SET_SIZE` call.
    pub const fn set_size(window: u64, size: u64) -> [u64; 4] {
        [SET_SIZE, window, size, 0]
    }

    /// Minimises window `window`: it stays shown (a manager lists it) but is
    /// drawn nowhere, and the front window takes the keyboard focus if it had
    /// it, until a manager activates it (or its own client raises it). A
    /// manager's, for any other client's window, or the window's own client's;
    /// `Denied` for another client's.
    pub const MINIMISE: u64 = 16;
    /// The message of a `MINIMISE` call.
    pub const fn minimise(window: u64) -> [u64; 4] {
        [MINIMISE, window, 0, 0]
    }

    /// Says what the window is: `icon`, a number the desktop shell knows
    /// (the toolkit's icons; 0 none).
    pub const SET_ICON: u64 = 17;
    /// The message of a `SET_ICON` call.
    pub const fn set_icon(window: u64, icon: u64) -> [u64; 4] {
        [SET_ICON, window, icon, 0]
    }

    /// A manager's: what window `window`'s client says it is (`SET_ICON`).
    pub const ICON: u64 = 18;
    /// The message of a `ICON` call.
    pub const fn icon(window: u64) -> [u64; 4] {
        [ICON, window, 0, 0]
    }
    /// What a `ICON` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct IconReply {
        pub icon: u64,
    }
    /// Reads a `ICON` reply: its results, or the status it failed with.
    pub fn icon_reply(m: [u64; 4]) -> Result<IconReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(IconReply {
                icon: m[1],
            }),
            s => Err(s),
        }
    }

    /// Puts 8 bytes in the clipboard at byte `8 * part` (`bytes`, the first in
    /// its low byte); part 0 empties it first. Its text ends at its first zero
    /// byte. `Denied` unless the window has the keyboard focus; `Invalid` past
    /// `CLIPBOARD_BYTES`.
    pub const CLIP_PUT: u64 = 19;
    /// The message of a `CLIP_PUT` call.
    pub const fn clip_put(window: u64, part: u64, bytes: u64) -> [u64; 4] {
        [CLIP_PUT, window, part, bytes]
    }

    /// The clipboard's 8 bytes at byte `8 * part` (as `CLIP_PUT` takes them) and
    /// how long its text is. `Denied` unless the window has the keyboard focus;
    /// `Invalid` past `CLIPBOARD_BYTES`.
    pub const CLIP_GET: u64 = 20;
    /// The message of a `CLIP_GET` call.
    pub const fn clip_get(window: u64, part: u64) -> [u64; 4] {
        [CLIP_GET, window, part, 0]
    }
    /// What a `CLIP_GET` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ClipGetReply {
        pub bytes: u64,
        pub len: u64,
    }
    /// Reads a `CLIP_GET` reply: its results, or the status it failed with.
    pub fn clip_get_reply(m: [u64; 4]) -> Result<ClipGetReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(ClipGetReply {
                bytes: m[1],
                len: m[2],
            }),
            s => Err(s),
        }
    }
}
