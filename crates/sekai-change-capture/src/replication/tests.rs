//! Fake streams: messages built byte by byte the way the output plugin
//! writes them, fed through the decoder and the line protocol.

use super::*;
use crate::output::{Line, MAX_LINE_BYTES};

const ITEMS: u32 = 16_384;
const TAGS: u32 = 16_385;

/// A message under construction.
struct Msg(Vec<u8>);

impl Msg {
    fn new(tag: u8) -> Self {
        Self(vec![tag])
    }
    fn u8(mut self, value: u8) -> Self {
        self.0.push(value);
        self
    }
    fn u16(mut self, value: u16) -> Self {
        self.0.extend(value.to_be_bytes());
        self
    }
    fn u32(mut self, value: u32) -> Self {
        self.0.extend(value.to_be_bytes());
        self
    }
    fn u64(mut self, value: u64) -> Self {
        self.0.extend(value.to_be_bytes());
        self
    }
    fn cstr(mut self, text: &str) -> Self {
        self.0.extend(text.as_bytes());
        self.0.push(0);
        self
    }
    /// A tuple of text values, `None` for null.
    fn tuple(mut self, tag: u8, values: &[Option<&str>]) -> Self {
        self = self.u8(tag).u16(values.len() as u16);
        for value in values {
            self = match value {
                None => self.u8(b'n'),
                Some(text) => {
                    let mut msg = self.u8(b't').u32(text.len() as u32);
                    msg.0.extend(text.as_bytes());
                    msg
                }
            };
        }
        self
    }
}

/// A relation with a key column `id` and a value column `name`.
fn relation(oid: u32, name: &str) -> Vec<u8> {
    Msg::new(b'R')
        .u32(oid)
        .cstr("public")
        .cstr(name)
        .u8(b'd')
        .u16(2)
        .u8(1)
        .cstr("id")
        .u32(23)
        .u32(u32::MAX)
        .u8(0)
        .cstr("name")
        .u32(25)
        .u32(u32::MAX)
        .0
}

fn begin(commit_lsn: u64) -> Vec<u8> {
    Msg::new(b'B').u64(commit_lsn).u64(0).u32(7).0
}

fn commit(commit_lsn: u64, end_lsn: u64) -> Vec<u8> {
    Msg::new(b'C').u8(0).u64(commit_lsn).u64(end_lsn).u64(0).0
}

fn insert(oid: u32, id: &str, name: Option<&str>) -> Vec<u8> {
    Msg::new(b'I').u32(oid).tuple(b'N', &[Some(id), name]).0
}

/// Decodes a whole stream; the first refusal ends it.
fn run(decoder: &mut Decoder, stream: &[Vec<u8>]) -> Result<Vec<Change>, DecodeError> {
    let mut out = Vec::new();
    for message in stream {
        out.extend(decoder.decode(message)?);
    }
    Ok(out)
}

fn positions(changes: &[Change]) -> Vec<(u64, Option<u32>)> {
    changes
        .iter()
        .map(|change| match change {
            Change::Row {
                commit_lsn, index, ..
            }
            | Change::Truncate {
                commit_lsn, index, ..
            } => (*commit_lsn, Some(*index)),
            Change::Commit { commit_lsn, .. } => (*commit_lsn, None),
        })
        .collect()
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

#[test]
fn decodes_insert_update_and_delete_with_their_keys() {
    let stream = [
        relation(ITEMS, "items"),
        begin(100),
        insert(ITEMS, "1", Some("a")),
        // An update that changed the key carries the old one.
        Msg::new(b'U')
            .u32(ITEMS)
            .tuple(b'K', &[Some("1"), None])
            .tuple(b'N', &[Some("2"), Some("b")])
            .0,
        // A null value.
        Msg::new(b'U').u32(ITEMS).tuple(b'N', &[Some("2"), None]).0,
        Msg::new(b'D').u32(ITEMS).tuple(b'K', &[Some("2"), None]).0,
        commit(100, 108),
    ];
    let changes = run(&mut Decoder::default(), &stream).unwrap();
    let row = |change: &Change| match change {
        Change::Row {
            op,
            key,
            row,
            relation,
            ..
        } => (*op, key.clone(), row.clone(), relation.clone()),
        other => panic!("not a row: {other:?}"),
    };
    let key = |id: &str| BTreeMap::from([("id".to_owned(), text(id))]);

    let (op, k, r, relation) = row(&changes[0]);
    assert_eq!(
        (op, k, relation.as_str()),
        (RowOp::Insert, key("1"), "public.items")
    );
    assert_eq!(
        r,
        vec![("id".to_owned(), text("1")), ("name".to_owned(), text("a"))]
    );

    let (op, k, r, _) = row(&changes[1]);
    assert_eq!((op, k), (RowOp::Update, key("1")));
    assert_eq!(r[0], ("id".to_owned(), text("2")));

    let (op, k, r, _) = row(&changes[2]);
    assert_eq!(
        (op, k, r[1].1.clone()),
        (RowOp::Update, key("2"), Value::Null)
    );

    let (op, k, r, _) = row(&changes[3]);
    assert_eq!((op, k, r.len()), (RowOp::Delete, key("2"), 0));

    assert_eq!(
        changes[4],
        Change::Commit {
            commit_lsn: 100,
            end_lsn: 108
        }
    );
}

#[test]
fn unchanged_values_reach_the_line_apart_from_the_row() {
    let mut decoder = Decoder::default();
    decoder.decode(&relation(ITEMS, "items")).unwrap();
    decoder.decode(&begin(100)).unwrap();
    let update = Msg::new(b'U')
        .u32(ITEMS)
        .u8(b'N')
        .u16(2)
        .u8(b't')
        .u32(1)
        .u8(b'1')
        .u8(b'u')
        .0;
    let line = Line::from(decoder.decode(&update).unwrap().unwrap());
    let Line::Change {
        row,
        unchanged,
        key,
        ..
    } = &line
    else {
        panic!("{line:?}")
    };
    assert_eq!(
        row,
        &BTreeMap::from([("id".to_owned(), Some("1".to_owned()))])
    );
    assert_eq!(unchanged, &["name".to_owned()]);
    assert_eq!(key, row);
}

#[test]
fn orders_changes_within_and_across_transactions() {
    let stream = [
        relation(ITEMS, "items"),
        relation(TAGS, "tags"),
        begin(100),
        insert(ITEMS, "1", Some("a")),
        insert(TAGS, "1", None),
        insert(ITEMS, "2", Some("b")),
        commit(100, 108),
        // Relation and type messages between transactions change nothing.
        Msg::new(b'Y').u32(9).cstr("public").cstr("mood").0,
        begin(200),
        insert(TAGS, "2", None),
        commit(200, 208),
    ];
    let changes = run(&mut Decoder::default(), &stream).unwrap();
    assert_eq!(
        positions(&changes),
        [
            (100, Some(0)),
            (100, Some(1)),
            (100, Some(2)),
            (100, None),
            (200, Some(0)),
            (200, None)
        ]
    );
    let lines: Vec<String> = changes
        .into_iter()
        .map(|change| Line::from(change).encode().unwrap())
        .collect();
    for line in &lines {
        assert_eq!(line.matches('\n').count(), 1);
        Line::parse(line).unwrap();
    }
}

#[test]
fn refuses_a_transaction_that_does_not_advance() {
    let mut decoder = Decoder::default();
    run(
        &mut decoder,
        &[relation(ITEMS, "items"), begin(200), commit(200, 208)],
    )
    .unwrap();
    assert_eq!(decoder.decode(&begin(200)), Err(DecodeError::OutOfOrder));
    assert_eq!(decoder.decode(&begin(150)), Err(DecodeError::OutOfOrder));

    let mut resumed = Decoder::resuming_after(200);
    assert_eq!(resumed.decode(&begin(200)), Err(DecodeError::OutOfOrder));
    assert_eq!(resumed.decode(&begin(201)), Ok(None));
}

#[test]
fn refuses_changes_outside_their_transaction() {
    let mut outside = Decoder::default();
    outside.decode(&relation(ITEMS, "items")).unwrap();
    assert_eq!(
        outside.decode(&insert(ITEMS, "1", None)),
        Err(DecodeError::OutOfTransaction)
    );

    let mut nested = Decoder::default();
    nested.decode(&begin(100)).unwrap();
    assert_eq!(
        nested.decode(&begin(200)),
        Err(DecodeError::OutOfTransaction)
    );

    let mut mismatched = Decoder::default();
    mismatched.decode(&begin(100)).unwrap();
    assert_eq!(
        mismatched.decode(&commit(101, 108)),
        Err(DecodeError::OutOfTransaction)
    );

    assert_eq!(
        Decoder::default().decode(&commit(100, 108)),
        Err(DecodeError::OutOfTransaction)
    );
}

#[test]
fn decodes_truncate_in_order() {
    let stream = [
        relation(ITEMS, "items"),
        relation(TAGS, "tags"),
        begin(100),
        insert(ITEMS, "1", None),
        Msg::new(b'T').u32(2).u8(1).u32(ITEMS).u32(TAGS).0,
        commit(100, 108),
    ];
    let changes = run(&mut Decoder::default(), &stream).unwrap();
    assert_eq!(
        changes[1],
        Change::Truncate {
            commit_lsn: 100,
            index: 1,
            relations: vec!["public.items".to_owned(), "public.tags".to_owned()],
        }
    );
    let line = Line::from(changes[1].clone()).encode().unwrap();
    assert_eq!(
        line,
        "{\"kind\":\"truncate\",\"commit_lsn\":100,\"index\":1,\"relations\":[\"public.items\",\"public.tags\"]}\n"
    );
}

#[test]
fn refuses_an_unknown_relation() {
    for message in [
        insert(TAGS, "1", None),
        Msg::new(b'D').u32(TAGS).tuple(b'K', &[Some("1"), None]).0,
        Msg::new(b'T').u32(2).u8(0).u32(ITEMS).u32(TAGS).0,
    ] {
        let mut decoder = Decoder::default();
        run(&mut decoder, &[relation(ITEMS, "items"), begin(100)]).unwrap();
        let refused = decoder.decode(&message).unwrap_err();
        assert_eq!(refused, DecodeError::UnknownRelation);
        assert_eq!(
            Line::from(refused).encode().unwrap(),
            "{\"kind\":\"refused\",\"reason\":\"unknown_relation\"}\n"
        );
    }
}

#[test]
fn refuses_malformed_messages() {
    let well_formed = insert(ITEMS, "1", Some("a"));
    let mut cases = vec![
        (Vec::new(), DecodeError::Malformed),
        (vec![b'?'], DecodeError::Malformed),
        (
            well_formed[..well_formed.len() - 1].to_vec(),
            DecodeError::Malformed,
        ),
        (
            [well_formed.clone(), vec![0]].concat(),
            DecodeError::Malformed,
        ),
        // One column where the relation has two.
        (
            Msg::new(b'I').u32(ITEMS).tuple(b'N', &[Some("1")]).0,
            DecodeError::Malformed,
        ),
        // A length past the end of the message.
        (
            Msg::new(b'I')
                .u32(ITEMS)
                .u8(b'N')
                .u16(2)
                .u8(b't')
                .u32(u32::MAX)
                .0,
            DecodeError::Malformed,
        ),
        (
            Msg::new(b'I')
                .u32(ITEMS)
                .u8(b'N')
                .u16(2)
                .u8(b'n')
                .u8(b'?')
                .0,
            DecodeError::Malformed,
        ),
        (
            Msg::new(b'I')
                .u32(ITEMS)
                .u8(b'N')
                .u16(2)
                .u8(b'n')
                .u8(b'b')
                .0,
            DecodeError::Unsupported,
        ),
        (
            Msg::new(b'I').u32(ITEMS).tuple(b'K', &[Some("1"), None]).0,
            DecodeError::Malformed,
        ),
        (
            Msg::new(b'I')
                .u32(ITEMS)
                .u8(b'N')
                .u16(2)
                .u8(b't')
                .u32(1)
                .u8(0xff)
                .u8(b'n')
                .0,
            DecodeError::NotUtf8,
        ),
        (vec![b'S'], DecodeError::Unsupported),
        // A relation declaring more columns than any table may have.
        (
            Msg::new(b'R')
                .u32(1)
                .cstr("s")
                .cstr("t")
                .u8(b'd')
                .u16(1601)
                .0,
            DecodeError::Oversize,
        ),
        (
            Msg::new(b'R')
                .u32(1)
                .cstr("s")
                .cstr("t")
                .u8(b'd')
                .u16(u16::MAX)
                .0,
            DecodeError::Malformed,
        ),
        (Msg::new(b'T').u32(u32::MAX).u8(0).0, DecodeError::Oversize),
    ];
    cases.push((vec![b'I'; MAX_MESSAGE_BYTES + 1], DecodeError::Oversize));
    for (index, (message, expected)) in cases.into_iter().enumerate() {
        let mut decoder = Decoder::default();
        run(&mut decoder, &[relation(ITEMS, "items"), begin(100)]).unwrap();
        assert_eq!(decoder.decode(&message), Err(expected), "case {index}");
    }
}

#[test]
fn parses_log_and_keepalive_frames() {
    let payload = begin(100);
    let log = [Msg::new(b'w').u64(90).u64(120).u64(0).0, payload.clone()].concat();
    assert_eq!(
        Frame::parse(&log),
        Ok(Frame::Log {
            wal_start: 90,
            wal_end: 120,
            data: &payload
        })
    );

    let keepalive = Msg::new(b'k').u64(120).u64(0).u8(1).0;
    assert_eq!(
        Frame::parse(&keepalive),
        Ok(Frame::Keepalive {
            wal_end: 120,
            reply_requested: true
        })
    );

    for refused in [
        Msg::new(b'k').u64(120).u64(0).u8(2).0,
        Msg::new(b'k').u64(120).u64(0).u8(0).u8(0).0,
        Msg::new(b'w').u64(90).0,
        vec![b'x'],
    ] {
        assert_eq!(Frame::parse(&refused), Err(DecodeError::Malformed));
    }
    assert_eq!(
        Frame::parse(&vec![b'w'; MAX_MESSAGE_BYTES + 1]),
        Err(DecodeError::Oversize)
    );
}

#[test]
fn line_protocol_round_trips_and_bounds_input() {
    let line = Line::Commit {
        commit_lsn: 100,
        end_lsn: 108,
    };
    assert_eq!(Line::parse(&line.encode().unwrap()), Ok(line));
    assert_eq!(
        Line::parse("{\"kind\":\"commit\",\"commit_lsn\":1}"),
        Err(DecodeError::Malformed)
    );
    assert_eq!(
        Line::parse("{\"kind\":\"commit\",\"commit_lsn\":1,\"end_lsn\":2,\"extra\":0}"),
        Err(DecodeError::Malformed)
    );
    assert_eq!(
        Line::parse(&" ".repeat(MAX_LINE_BYTES + 1)),
        Err(DecodeError::Oversize)
    );
}
