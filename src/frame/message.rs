use crate::types::{RawTypedData, TypedData, TypedDataRef};
use bytes::Bytes;
use std::{fmt, iter::FusedIterator, slice};

/// Represents a message in the list of messages.
/// ```text
///     LIST-OF-MESSAGES : [ <MESSAGE-NAME> <NB-ARGS:1 byte> <KV-LIST> ... ]
///     MESSAGE-NAME     : <STRING>
/// ```
///
/// A decoded message keeps the frame it arrived in and points into it: its name, its argument
/// names, valid STRING values and BINARY values are read from there. Invalid UTF-8 text
/// needs a separate allocation for its replacement characters.
/// A message can keep the entire socket read allocation alive, including capacity shared with
/// other frames. Use [`TypedDataRef::into_owned`] for individual values that outlive it.
#[derive(Clone)]
pub struct Message {
    /// The bytes that `name` and `args` point into.
    buf: Bytes,
    name: Text,
    args: Vec<Arg>,
}

impl Message {
    /// Builds a message, for instance to test a handler without a frame.
    #[must_use]
    pub fn new<N: AsRef<str>>(name: &str, args: impl IntoIterator<Item = (N, TypedData)>) -> Self {
        let args: Vec<(N, TypedData)> = args.into_iter().collect();

        // Lay the strings out the way a frame would hold them, then point into them.
        let mut buf = name.as_bytes().to_vec();
        let mut ranges = Vec::with_capacity(args.len());
        for (arg_name, value) in &args {
            let name_start = buf.len();
            buf.extend_from_slice(arg_name.as_ref().as_bytes());
            let value_start = buf.len();
            match value {
                TypedData::String(s) => buf.extend_from_slice(s.as_bytes()),
                TypedData::Binary(b) => buf.extend_from_slice(b),
                _ => {}
            }
            ranges.push((name_start, value_start, buf.len()));
        }

        let buf = Bytes::from(buf);
        let slicer = Slicer::new(&buf);
        let at = |start: usize, end: usize| buf.get(start..end).unwrap_or_default();
        let message_args = args
            .iter()
            .zip(ranges)
            .map(|((_, value), (name_start, value_start, end))| {
                let raw = match value {
                    TypedData::String(_) => RawTypedData::String(at(value_start, end)),
                    TypedData::Binary(_) => RawTypedData::Binary(at(value_start, end)),
                    scalar => RawTypedData::Scalar(scalar.scalar().unwrap_or(TypedDataRef::Null)),
                };
                slicer.arg(at(name_start, value_start), raw)
            })
            .collect();
        let name = slicer.text(at(0, name.len()));
        let mut message = Slicer::message(name, message_args);
        message.attach(buf);
        message
    }

    /// Validate every text range against its final, immutable owner before exposing it.
    pub(crate) fn attach(&mut self, body: Bytes) {
        self.name.validate(&body);
        for arg in &mut self.args {
            arg.name.validate(&body);
            if let Value::String(text) = &mut arg.value {
                text.validate(&body);
            }
        }
        self.buf = body;
    }

    /// The message name, as declared by `spoe-message`.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.resolve(&self.buf)
    }

    /// The arguments, in the order they are declared in the `spoe-message` section, which is
    /// the order `HAProxy` sends them.
    ///
    /// Argument names are optional (`args [name=]<sample> ...`), so a name may be empty and
    /// may repeat: `args frontend=fe_id src dst` arrives as `("frontend", ..)`, `("", ..)`,
    /// `("", ..)`. Use [`Message::get`] to look one up by name.
    #[must_use]
    pub fn args(&self) -> Args<'_> {
        Args {
            buf: &self.buf,
            args: self.args.iter(),
        }
    }

    /// Returns the value of the first argument named `name`.
    ///
    /// Messages carry at most 255 arguments (NB-ARGS is one byte), and usually a handful, so
    /// this is a linear scan.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<TypedDataRef<'_>> {
        self.args()
            .find(|(arg_name, _)| *arg_name == name)
            .map(|(_, value)| value)
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("name", &self.name())
            .field("args", &self.args())
            .finish()
    }
}

/// Iterator over the arguments of a [`Message`], as `(name, value)` pairs.
#[derive(Clone)]
pub struct Args<'a> {
    buf: &'a [u8],
    args: slice::Iter<'a, Arg>,
}

impl<'a> Iterator for Args<'a> {
    type Item = (&'a str, TypedDataRef<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        self.args.next().map(|arg| arg.resolve(self.buf))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.args.size_hint()
    }
}

impl DoubleEndedIterator for Args<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.args.next_back().map(|arg| arg.resolve(self.buf))
    }
}

impl ExactSizeIterator for Args<'_> {}

impl FusedIterator for Args<'_> {}

impl fmt::Debug for Args<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

/// Builds messages whose names and values point into `buf`.
pub(crate) struct Slicer<'a> {
    buf: &'a [u8],
}

impl<'a> Slicer<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub(crate) fn message(name: Text, args: Vec<Arg>) -> Message {
        Message {
            buf: Bytes::new(),
            name,
            args,
        }
    }

    /// An argument whose name and payload are slices of `buf`.
    pub(crate) fn arg(&self, name: &[u8], value: RawTypedData<'_>) -> Arg {
        let value = match value {
            RawTypedData::Scalar(value) => Value::Scalar(value),
            RawTypedData::String(data) => Value::String(self.text(data)),
            RawTypedData::Binary(data) => Value::Binary(self.span(data)),
        };
        Arg {
            name: self.text(name),
            value,
        }
    }

    /// Record a text range. Attaching the body validates it and replaces invalid UTF-8.
    pub(crate) fn text(&self, data: &[u8]) -> Text {
        Text::Span(self.span(data))
    }

    fn span(&self, data: &[u8]) -> Span {
        let start = data.as_ptr().addr().wrapping_sub(self.buf.as_ptr().addr());
        let span = Span {
            start,
            end: start.saturating_add(data.len()),
        };
        debug_assert!(
            span.end <= self.buf.len(),
            "slice outside the message buffer"
        );
        span
    }
}

/// A range of a message's buffer.
#[derive(Clone, Copy)]
pub(crate) struct Span {
    start: usize,
    end: usize,
}

impl Span {
    fn slice(self, buf: &[u8]) -> &[u8] {
        buf.get(self.start..self.end).unwrap_or_default()
    }
}

#[derive(Clone)]
pub(crate) enum Text {
    /// Relative to the body. Checked before the body is attached.
    Span(Span),
    /// The input was not valid UTF-8.
    Replaced(Box<str>),
}

impl Text {
    fn validate(&mut self, body: &[u8]) {
        let Self::Span(span) = self else { return };
        let bytes = span.slice(body);
        if std::str::from_utf8(bytes).is_err() {
            *self = Self::Replaced(String::from_utf8_lossy(bytes).into());
        }
    }

    fn resolve<'a>(&'a self, buf: &'a [u8]) -> &'a str {
        match self {
            // SAFETY: Message::attach validates each range against this immutable Bytes
            // before installing it. An unattached message resolves spans against an empty slice.
            Self::Span(span) => unsafe { std::str::from_utf8_unchecked(span.slice(buf)) },
            Self::Replaced(text) => text,
        }
    }
}

#[derive(Clone)]
enum Value {
    Scalar(TypedDataRef<'static>),
    String(Text),
    Binary(Span),
}

#[derive(Clone)]
pub(crate) struct Arg {
    name: Text,
    value: Value,
}

impl Arg {
    fn resolve<'a>(&'a self, buf: &'a [u8]) -> (&'a str, TypedDataRef<'a>) {
        let value = match &self.value {
            Value::Scalar(value) => *value,
            Value::String(text) => TypedDataRef::String(text.resolve(buf)),
            Value::Binary(span) => TypedDataRef::Binary(span.slice(buf)),
        };
        (self.name.resolve(buf), value)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn new_message_reads_back() {
        let message = Message::new(
            "check",
            [
                ("ip", TypedData::IPv4(Ipv4Addr::new(192, 0, 2, 1))),
                ("", TypedData::String("unnamed".to_string())),
                ("body", TypedData::Binary(vec![0, 159, 146, 150])),
                ("ip", TypedData::Null),
            ],
        );

        assert_eq!(message.name(), "check");
        assert_eq!(
            message.args().collect::<Vec<_>>(),
            vec![
                ("ip", TypedDataRef::IPv4(Ipv4Addr::new(192, 0, 2, 1))),
                ("", TypedDataRef::String("unnamed")),
                ("body", TypedDataRef::Binary(&[0, 159, 146, 150])),
                ("ip", TypedDataRef::Null),
            ]
        );
        assert_eq!(
            message.get("ip"),
            Some(TypedDataRef::IPv4(Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert_eq!(message.get("missing"), None);
        assert_eq!(message.args().len(), 4);
        assert_eq!(message.args().next_back().unwrap().0, "ip");
    }

    #[test]
    fn invalid_utf8_is_replaced() {
        let buf = Bytes::from_static(b"ok\xffbad");
        let slicer = Slicer::new(&buf);
        let mut message = Slicer::message(
            slicer.text(buf.get(0..2).unwrap()),
            vec![slicer.arg(
                buf.get(2..6).unwrap(),
                RawTypedData::String(buf.get(0..2).unwrap()),
            )],
        );

        message.attach(buf);
        assert_eq!(message.name(), "ok");
        assert_eq!(
            message.args().collect::<Vec<_>>(),
            vec![("\u{FFFD}bad", TypedDataRef::String("ok"))]
        );
    }

    #[test]
    fn debug_shows_the_values() {
        let message = Message::new("m", [("a", TypedData::from("x"))]);
        assert_eq!(
            format!("{message:?}"),
            r#"Message { name: "m", args: [("a", String("x"))] }"#
        );
    }
}
