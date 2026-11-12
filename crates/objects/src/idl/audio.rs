// Generated from interfaces/audio.idl by the IDL compiler (`cargo xtask idl`).
// Do not edit: change the description and generate again.

/// Audio playback: what a sound driver serves, and the mixer as well (to
/// many callers at once: it adds their streams together and plays the sum
/// through the driver). Samples are signed 16-bit little-endian, two
/// channels interleaved, left first: a frame is 4 bytes. A caller writes
/// frames into a ring of its own pages, lent to the server a page at a
/// time, and says how far it has written; the server plays them in order
/// at its rate. Positions count frames since `START`: frame n lies at byte
/// (n mod RING_FRAMES) * 4 of the ring. A caller sees and changes only its
/// own stream (the capability's badge says whose).
///
/// When the server has played every frame written it plays silence. A
/// sound driver's count of frames played runs on meanwhile, and frames
/// written below it are never played, so a caller that fell behind writes
/// on from `played`; the mixer's waits for the caller instead. Crash-only:
/// a restarted server knows no ring, refuses the next call (`Invalid`), and
/// the caller sets its stream up again.
pub mod audio {
    use crate::interfaces::Status;

    pub const VERSION: u64 = 1;

    /// The pages of a ring (64 KiB), and the frames it holds.
    pub const RING_PAGES: u64 = 16;

    pub const RING_FRAMES: u64 = 16384;

    /// The rate frames are played at (Hz); how many streams are started (every
    /// caller's), and how many of them have frames written and not yet played.
    pub const INFO: u64 = 1;
    /// The message of a `INFO` call.
    pub const fn info() -> [u64; 4] {
        [INFO, VERSION, 0, 0]
    }
    /// What a `INFO` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct InfoReply {
        pub rate: u64,
        pub streams: u64,
        pub playing: u64,
    }
    /// Reads a `INFO` reply: its results, or the status it failed with.
    pub fn info_reply(m: [u64; 4]) -> Result<InfoReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(InfoReply {
                rate: m[1],
                streams: m[2],
                playing: m[3],
            }),
            s => Err(s),
        }
    }

    /// Keeps page `page` of the caller's ring, which the call lends. Pages come
    /// in order from 0; attaching page 0 again starts a new ring, and stops the
    /// caller's stream.
    pub const ATTACH: u64 = 2;
    /// The message of a `ATTACH` call.
    pub const fn attach(page: u64) -> [u64; 4] {
        [ATTACH, page, 0, 0]
    }

    /// Has the server signal the notification the call lends whenever frames
    /// of the caller's stream have been played (at most once a period of the
    /// device's), in place of one lent before.
    pub const LISTEN: u64 = 3;
    /// The message of a `LISTEN` call.
    pub const fn listen() -> [u64; 4] {
        [LISTEN, 0, 0, 0]
    }

    /// Starts the caller's stream at frame 0, once all of its ring is
    /// attached. Returns the frames in one of the device's periods.
    pub const START: u64 = 4;
    /// The message of a `START` call.
    pub const fn start() -> [u64; 4] {
        [START, 0, 0, 0]
    }
    /// What a `START` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct StartReply {
        pub period: u64,
    }
    /// Reads a `START` reply: its results, or the status it failed with.
    pub fn start_reply(m: [u64; 4]) -> Result<StartReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(StartReply {
                period: m[1],
            }),
            s => Err(s),
        }
    }

    /// The caller has written its ring up to frame `written` (never less than
    /// before, and no further than `limit` said). Returns how many frames of
    /// the stream have been played, and how far the caller may now write: the
    /// ring holds frames from what the server has not yet taken to there.
    pub const COMMIT: u64 = 5;
    /// The message of a `COMMIT` call.
    pub const fn commit(written: u64) -> [u64; 4] {
        [COMMIT, written, 0, 0]
    }
    /// What a `COMMIT` call answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CommitReply {
        pub played: u64,
        pub limit: u64,
    }
    /// Reads a `COMMIT` reply: its results, or the status it failed with.
    pub fn commit_reply(m: [u64; 4]) -> Result<CommitReply, Status> {
        match Status::from_u64(m[0]) {
            Status::Ok => Ok(CommitReply {
                played: m[1],
                limit: m[2],
            }),
            s => Err(s),
        }
    }

    /// Stops the caller's stream; what it had not played is dropped.
    pub const STOP: u64 = 6;
    /// The message of a `STOP` call.
    pub const fn stop() -> [u64; 4] {
        [STOP, 0, 0, 0]
    }
}
