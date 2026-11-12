//! The interface description language and its compiler (spec section 5).
//!
//! An interface is the operations a server takes over IPC: each a number
//! in the call's first message word, up to three argument words, and a
//! reply of a status and up to three result words. A description says so
//! once; [`compile`] makes the Rust both sides use: the numbers, a
//! function that builds each call's message, and one that reads its
//! reply.
//!
//! ```text
//! # What the interface is for.
//! interface pci version 1
//!
//! const MAX_THINGS = 8
//!
//! # What the operation does.
//! op OPEN = 1 (version, ids, instance) -> (location, memory_bars, io_bars)
//! op CLOSE = 12
//! ```
//!
//! A `#` line is a comment; those straight before an item become its
//! documentation. The argument named `version` is filled in with the
//! interface's version, not passed. Capabilities that travel with a call
//! are the caller's business (which slot to lend from or accept into),
//! and are not described yet.

use std::fmt::Write;

/// An operation's arguments and results fit a message's last three words.
pub const WORDS: usize = 3;

#[derive(Debug, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub version: u64,
    pub doc: Vec<String>,
    pub consts: Vec<Const>,
    pub ops: Vec<Op>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Const {
    pub name: String,
    pub value: u64,
    pub doc: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Op {
    pub name: String,
    pub number: u64,
    pub args: Vec<String>,
    pub results: Vec<String>,
    pub doc: Vec<String>,
}

/// What is wrong with a description, and on which line (from 1).
#[derive(Debug, PartialEq, Eq)]
pub struct Error {
    pub line: usize,
    pub what: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.what)
    }
}

fn is_name(s: &str, upper: bool) -> bool {
    let ok = |c: char| c == '_' || c.is_ascii_digit() || if upper { c.is_ascii_uppercase() } else { c.is_ascii_lowercase() };
    !s.is_empty() && !s.starts_with(|c: char| c.is_ascii_digit()) && s.chars().all(ok)
}

fn number(s: &str) -> Option<u64> {
    match s.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

/// The names in `(a, b, c)`; the rest of the line after it.
fn list(s: &str) -> Result<(Vec<String>, &str), String> {
    let s = s.trim_start();
    let Some(inner) = s.strip_prefix('(') else {
        return Ok((Vec::new(), s));
    };
    let end = inner.find(')').ok_or("a list is not closed")?;
    let names: Vec<String> = inner[..end]
        .split(',')
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .collect();
    if let Some(bad) = names.iter().find(|n| !is_name(n, false)) {
        return Err(format!("`{bad}` is not a lower-case name"));
    }
    if names.len() > WORDS + names.iter().any(|n| n == "version") as usize {
        return Err(format!("more than {WORDS} words"));
    }
    if (1..names.len()).any(|i| names[..i].contains(&names[i])) {
        return Err("a name is used twice".into());
    }
    Ok((names, &inner[end + 1..]))
}

/// Reads a description.
pub fn parse(text: &str) -> Result<Interface, Error> {
    let mut interface: Option<Interface> = None;
    let mut doc = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let err = |what: String| Error { line: n + 1, what };
        let line = raw.trim();
        if let Some(comment) = line.strip_prefix('#') {
            doc.push(comment.strip_prefix(' ').unwrap_or(comment).to_string());
            continue;
        }
        if line.is_empty() {
            // A comment set apart from an item is not its documentation.
            doc.clear();
            continue;
        }
        let (word, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        let rest = rest.trim();
        let doc = std::mem::take(&mut doc);
        if word == "interface" {
            if interface.is_some() {
                return Err(err("a second interface".into()));
            }
            let mut words = rest.split_whitespace();
            let (name, version) = match (words.next(), words.next(), words.next(), words.next()) {
                (Some(name), Some("version"), Some(v), None) if is_name(name, false) => {
                    (name, number(v).ok_or_else(|| err(format!("`{v}` is not a number")))?)
                }
                _ => return Err(err("expected `interface <name> version <number>`".into())),
            };
            interface = Some(Interface {
                name: name.to_string(),
                version,
                doc,
                consts: Vec::new(),
                ops: Vec::new(),
            });
            continue;
        }
        let Some(i) = interface.as_mut() else {
            return Err(err("the interface line comes first".into()));
        };
        let (name, value) = rest
            .split_once('=')
            .map(|(a, b)| (a.trim(), b.trim()))
            .ok_or_else(|| err("expected `<NAME> = <number>`".into()))?;
        if !is_name(name, true) {
            return Err(err(format!("`{name}` is not an upper-case name")));
        }
        if name == "VERSION" || i.consts.iter().any(|c| c.name == name) || i.ops.iter().any(|o| o.name == name) {
            return Err(err(format!("`{name}` is already taken")));
        }
        match word {
            "const" => {
                let value = number(value).ok_or_else(|| err(format!("`{value}` is not a number")))?;
                i.consts.push(Const {
                    name: name.to_string(),
                    value,
                    doc,
                });
            }
            "op" => {
                let (num, rest) = value.split_once(char::is_whitespace).unwrap_or((value, ""));
                let number = number(num).ok_or_else(|| err(format!("`{num}` is not a number")))?;
                if let Some(other) = i.ops.iter().find(|o| o.number == number) {
                    return Err(err(format!("{} already has number {number}", other.name)));
                }
                let (args, rest) = list(rest).map_err(&err)?;
                let rest = rest.trim();
                let results = match rest.strip_prefix("->") {
                    Some(r) => {
                        let (results, rest) = list(r).map_err(&err)?;
                        if !rest.trim().is_empty() || results.is_empty() {
                            return Err(err("expected `-> (result, ...)` and nothing after".into()));
                        }
                        if results.iter().any(|r| r == "version" || r == "status") {
                            return Err(err("`version` and `status` are not results".into()));
                        }
                        results
                    }
                    None if rest.is_empty() => Vec::new(),
                    None => return Err(err(format!("unexpected `{rest}`"))),
                };
                i.ops.push(Op {
                    name: name.to_string(),
                    number,
                    args,
                    results,
                    doc,
                });
            }
            other => return Err(err(format!("unknown item `{other}`"))),
        }
    }
    interface.ok_or(Error {
        line: text.lines().count().max(1),
        what: "no interface".into(),
    })
}

fn camel(upper: &str) -> String {
    upper
        .split('_')
        .map(|w| {
            let mut c = w.chars();
            c.next().map_or(String::new(), |f| f.to_string() + &c.as_str().to_lowercase())
        })
        .collect()
}

fn docs(out: &mut String, doc: &[String]) {
    for line in doc {
        let _ = writeln!(out, "///{}{line}", if line.is_empty() { "" } else { " " });
    }
}

/// The Rust for an interface: its version and constants, and for each
/// operation its number, a function building the call's message, and
/// (with results) a reply type and a function reading a reply into it.
/// `source` is named at the top, as where to make changes.
pub fn generate(i: &Interface, source: &str) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "// Generated from {source} by the IDL compiler (`cargo xtask idl`).");
    let _ = writeln!(out, "// Do not edit: change the description and generate again.\n");
    docs(&mut out, &i.doc);
    let _ = writeln!(out, "pub mod {} {{", i.name);
    let _ = writeln!(out, "    use crate::interfaces::Status;\n");
    let _ = writeln!(out, "    pub const VERSION: u64 = {};", i.version);
    let mut body = String::new();
    for c in &i.consts {
        let _ = writeln!(body);
        docs(&mut body, &c.doc);
        let _ = writeln!(body, "pub const {}: u64 = {};", c.name, c.value);
    }
    for op in &i.ops {
        let lower = op.name.to_lowercase();
        let _ = writeln!(body);
        docs(&mut body, &op.doc);
        let _ = writeln!(body, "pub const {}: u64 = {};", op.name, op.number);
        // The call's message.
        let params: Vec<String> = op
            .args
            .iter()
            .filter(|a| *a != "version")
            .map(|a| format!("{a}: u64"))
            .collect();
        let mut words: Vec<String> = op
            .args
            .iter()
            .map(|a| if a == "version" { "VERSION".into() } else { a.clone() })
            .collect();
        words.resize(WORDS, "0".into());
        let _ = writeln!(body, "/// The message of a `{}` call.", op.name);
        let _ = writeln!(
            body,
            "pub const fn {lower}({}) -> [u64; 4] {{\n    [{}, {}]\n}}",
            params.join(", "),
            op.name,
            words.join(", ")
        );
        if op.results.is_empty() {
            continue;
        }
        let reply = format!("{}Reply", camel(&op.name));
        let _ = writeln!(body, "/// What a `{}` call answers.", op.name);
        let _ = writeln!(body, "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct {reply} {{");
        for r in &op.results {
            let _ = writeln!(body, "    pub {r}: u64,");
        }
        let _ = writeln!(body, "}}");
        let _ = writeln!(body, "/// Reads a `{}` reply: its results, or the status it failed with.", op.name);
        let _ = writeln!(body, "pub fn {lower}_reply(m: [u64; 4]) -> Result<{reply}, Status> {{");
        let _ = writeln!(body, "    match Status::from_u64(m[0]) {{");
        let _ = writeln!(body, "        Status::Ok => Ok({reply} {{");
        for (k, r) in op.results.iter().enumerate() {
            let _ = writeln!(body, "            {r}: m[{}],", k + 1);
        }
        let _ = writeln!(body, "        }}),\n        s => Err(s),\n    }}\n}}");
    }
    for line in body.lines() {
        let _ = writeln!(out, "{}{line}", if line.is_empty() { "" } else { "    " });
    }
    let _ = writeln!(out, "}}");
    out
}

/// A description to Rust.
pub fn compile(text: &str, source: &str) -> Result<String, Error> {
    parse(text).map(|i| generate(&i, source))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALL: &str = "\
# A thing server.
# Second line.
interface thing version 3

# The most things.
const MAX_THINGS = 0x10

# Not attached: a blank line follows.

# Makes one.
op MAKE = 1 (version, kind, size) -> (handle)
op DROP = 2 (handle)
op COUNT = 7 -> (things, bytes, peak)
op RESET = 9
";

    #[test]
    fn parses_an_interface() {
        let i = parse(SMALL).unwrap();
        assert_eq!((i.name.as_str(), i.version), ("thing", 3));
        assert_eq!(i.doc, ["A thing server.", "Second line."]);
        assert_eq!(i.consts.len(), 1);
        assert_eq!((i.consts[0].name.as_str(), i.consts[0].value), ("MAX_THINGS", 16));
        assert_eq!(i.consts[0].doc, ["The most things."]);
        let ops: Vec<_> = i.ops.iter().map(|o| (o.name.as_str(), o.number, o.args.len(), o.results.len())).collect();
        assert_eq!(ops, [("MAKE", 1, 3, 1), ("DROP", 2, 1, 0), ("COUNT", 7, 0, 3), ("RESET", 9, 0, 0)]);
        // Only the comment straight before an item documents it.
        assert_eq!(i.ops[0].doc, ["Makes one."]);
        assert!(i.ops[1].doc.is_empty());
    }

    #[test]
    fn generates_numbers_messages_and_replies() {
        let rust = compile(SMALL, "interfaces/thing.idl").unwrap();
        for piece in [
            "// Generated from interfaces/thing.idl",
            "/// A thing server.\n/// Second line.\npub mod thing {",
            "    pub const VERSION: u64 = 3;",
            "    /// The most things.\n    pub const MAX_THINGS: u64 = 16;",
            "    /// Makes one.\n    pub const MAKE: u64 = 1;",
            // `version` is filled in, not passed.
            "    pub const fn make(kind: u64, size: u64) -> [u64; 4] {\n        [MAKE, VERSION, kind, size]\n    }",
            "    pub struct MakeReply {\n        pub handle: u64,\n    }",
            "    pub fn make_reply(m: [u64; 4]) -> Result<MakeReply, Status> {",
            "    pub const fn drop(handle: u64) -> [u64; 4] {\n        [DROP, handle, 0, 0]\n    }",
            "    pub const fn count() -> [u64; 4] {\n        [COUNT, 0, 0, 0]\n    }",
            "                things: m[1],\n                bytes: m[2],\n                peak: m[3],",
            "    pub const fn reset() -> [u64; 4] {\n        [RESET, 0, 0, 0]\n    }",
        ] {
            assert!(rust.contains(piece), "missing {piece:?} in:\n{rust}");
        }
        // No reply type for an operation that answers only a status.
        assert!(!rust.contains("DropReply") && !rust.contains("ResetReply"));
        // Generating is deterministic.
        assert_eq!(rust, compile(SMALL, "interfaces/thing.idl").unwrap());
    }

    fn error(text: &str) -> (usize, String) {
        let e = parse(text).unwrap_err();
        (e.line, e.what)
    }

    #[test]
    fn says_what_is_wrong_and_where() {
        let head = "interface t version 1\n";
        assert_eq!(error("").1, "no interface");
        assert_eq!(error("op A = 1").1, "the interface line comes first");
        assert_eq!(error("interface T version 1").0, 1);
        assert_eq!(error("interface t version one").1, "`one` is not a number");
        assert_eq!(error(&format!("{head}interface u version 1")), (2, "a second interface".into()));
        assert_eq!(error(&format!("{head}op a = 1")).1, "`a` is not an upper-case name");
        assert_eq!(error(&format!("{head}op A = x")).1, "`x` is not a number");
        assert_eq!(error(&format!("{head}op A = 1\nop B = 1")), (3, "A already has number 1".into()));
        assert_eq!(error(&format!("{head}op A = 1\nconst A = 2")).1, "`A` is already taken");
        assert_eq!(error(&format!("{head}const VERSION = 2")).1, "`VERSION` is already taken");
        assert_eq!(error(&format!("{head}op A = 1 (a, b, c, d)")).1, "more than 3 words");
        assert_eq!(error(&format!("{head}op A = 1 (a, a)")).1, "a name is used twice");
        assert_eq!(error(&format!("{head}op A = 1 (Bad)")).1, "`Bad` is not a lower-case name");
        assert_eq!(error(&format!("{head}op A = 1 (a")).1, "a list is not closed");
        assert_eq!(error(&format!("{head}op A = 1 -> (status)")).1, "`version` and `status` are not results");
        assert_eq!(error(&format!("{head}op A = 1 (a) junk")).1, "unexpected `junk`");
        assert_eq!(error(&format!("{head}thing A = 1")).1, "unknown item `thing`");
        // Version and three more words is allowed.
        assert!(parse(&format!("{head}op A = 1 (version, a, b)")).is_ok());
        assert_eq!(error(&format!("{head}op A = 1 (version, a, b, c, d)")).1, "more than 3 words");
    }
}
